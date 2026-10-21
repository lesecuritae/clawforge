//! The executor may read a raw address from `security_ip_resolutions` only
//! through the narrow just-in-time function of migration 0059.
use anyhow::Result;
use clawforge_storage::PostgresStore;
use serde_json::{json, Value};
use sqlx::{postgres::PgConnectOptions, ConnectOptions, PgPool};
use std::str::FromStr;
use uuid::Uuid;

#[tokio::test]
#[ignore = "requires explicit disposable owner and restricted executor database URLs"]
async fn executor_resolves_only_a_claimed_unexpired_non_simulated_block() -> Result<()> {
    let base = std::env::var("CLAWFORGE_TEST_DATABASE_URL")?;
    let executor_base = std::env::var("CLAWFORGE_TEST_EXECUTOR_DATABASE_URL")?;
    let api_base = std::env::var("CLAWFORGE_TEST_API_DATABASE_URL")?;
    let admin = PgPool::connect(&base).await?;
    let database = format!("incident_resolution_{}", Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE DATABASE {database}"))
        .execute(&admin)
        .await?;
    let url = |base: &str| -> Result<String> {
        Ok(PgConnectOptions::from_str(base)?
            .database(&database)
            .to_url_lossy()
            .to_string())
    };
    let (owner_url, executor_url, api_url) = (url(&base)?, url(&executor_base)?, url(&api_base)?);
    let result =
        tokio::spawn(async move { check(&owner_url, &executor_url, &api_url).await }).await;
    let cleanup = sqlx::query(&format!("DROP DATABASE {database} WITH (FORCE)"))
        .execute(&admin)
        .await;
    admin.close().await;
    cleanup?;
    result??;
    Ok(())
}

async fn action(owner: &PgPool, name: &str) -> Result<Uuid> {
    Ok(sqlx::query_scalar(
        "INSERT INTO actions(id,name,type,risk_level,required_scope,requires_approval,enabled) \
         VALUES($1,$2,'connector_action','low','agent:action:read',FALSE,TRUE) \
         ON CONFLICT(name) DO UPDATE SET enabled=TRUE RETURNING id",
    )
    .bind(Uuid::new_v4())
    .bind(name)
    .fetch_one(owner)
    .await?)
}

/// A request in status `starting`, as the executor holds it right after claim.
async fn starting(owner: &PgPool, action: Uuid, target: Value) -> Result<Uuid> {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO execution_requests(id,action_id,requested_by,status,approval_context) \
         VALUES($1,$2,'fixture','pending',$3)",
    )
    .bind(id)
    .bind(action)
    .bind(json!({"version": 1, "target": target}))
    .execute(owner)
    .await?;
    sqlx::query("UPDATE execution_requests SET status='starting' WHERE id=$1")
        .bind(id)
        .execute(owner)
        .await?;
    Ok(id)
}

async fn resolution(owner: &PgPool, pseudonym: &str, ip: &str, ttl: i64) -> Result<()> {
    sqlx::query(
        "INSERT INTO security_ip_resolutions(pseudonym,raw_ip,source,expires_at) \
         VALUES($1,$2::inet,'fixture',NOW()+($3*INTERVAL '1 second'))",
    )
    .bind(pseudonym)
    .bind(ip)
    .bind(ttl)
    .execute(owner)
    .await?;
    Ok(())
}

fn target(pseudonym: &str) -> Value {
    json!({"kind": "incident_source", "pseudonym": pseudonym, "ttl_seconds": 60})
}

async fn check(owner_url: &str, executor_url: &str, api_url: &str) -> Result<()> {
    let owner = PostgresStore::connect(owner_url).await?;
    let provision = include_str!("../../scripts/provision-db-roles.sh");
    let grants = provision
        .split("GRANT SELECT ON TABLE _sqlx_migrations, actions, execution_requests,")
        .nth(1)
        .expect("executor grants start")
        .split("GRANT SELECT ON ALL TABLES IN SCHEMA public TO clawforge_backup;")
        .next()
        .expect("executor grants end");
    sqlx::raw_sql(&format!(
        "GRANT SELECT ON TABLE _sqlx_migrations, actions, execution_requests,{grants}"
    ))
    .execute(owner.pool())
    .await?;
    let executor = PostgresStore::connect_runtime(executor_url).await?;
    let api = PgPool::connect(api_url).await?;
    let pool = owner.pool();

    let block = action(pool, "nftables.block_incident_source").await?;

    // Eligible: claimed, unexpired single-host resolution, real block action.
    resolution(pool, "ip-pseudonym:ok", "203.0.113.50", 600).await?;
    let ok = starting(pool, block, target("ip-pseudonym:ok")).await?;
    let resolved = executor
        .resolve_incident_source_for_apply(ok)
        .await?
        .expect("eligible request must resolve");
    assert_eq!(resolved.raw_ip, "203.0.113.50");
    assert_eq!(resolved.pseudonym, "ip-pseudonym:ok");
    assert!(
        !format!("{resolved:?}").contains("203.0.113.50"),
        "Debug output must not leak the address"
    );

    // IPv6 host resolves too.
    resolution(pool, "ip-pseudonym:v6", "2001:db8::7", 600).await?;
    let v6 = starting(pool, block, target("ip-pseudonym:v6")).await?;
    assert_eq!(
        executor
            .resolve_incident_source_for_apply(v6)
            .await?
            .unwrap()
            .raw_ip,
        "2001:db8::7"
    );

    // Not yet claimed (still pending): no address.
    let pending = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO execution_requests(id,action_id,requested_by,status,approval_context) \
         VALUES($1,$2,'fixture','pending',$3)",
    )
    .bind(pending)
    .bind(block)
    .bind(json!({"version": 1, "target": target("ip-pseudonym:ok")}))
    .execute(pool)
    .await?;
    assert!(executor
        .resolve_incident_source_for_apply(pending)
        .await?
        .is_none());

    // Expired resolution.
    resolution(pool, "ip-pseudonym:old", "203.0.113.51", -5).await?;
    let old = starting(pool, block, target("ip-pseudonym:old")).await?;
    assert!(executor
        .resolve_incident_source_for_apply(old)
        .await?
        .is_none());

    // Missing resolution.
    let missing = starting(pool, block, target("ip-pseudonym:none")).await?;
    assert!(executor
        .resolve_incident_source_for_apply(missing)
        .await?
        .is_none());

    // Simulation-only requests never release an address.
    let mut simulated = target("ip-pseudonym:ok");
    simulated["simulation_only"] = json!(true);
    let sim = starting(pool, block, simulated).await?;
    assert!(executor
        .resolve_incident_source_for_apply(sim)
        .await?
        .is_none());

    // A threat-intel target (not an incident source) and a non-block action.
    let indicator = starting(
        pool,
        block,
        json!({"kind": "threat_intel_indicator", "cidr": "203.0.113.9/32", "source": "t"}),
    )
    .await?;
    assert!(executor
        .resolve_incident_source_for_apply(indicator)
        .await?
        .is_none());
    let challenge = action(pool, "goaway.challenge_incident_source").await?;
    let wrong = starting(pool, challenge, target("ip-pseudonym:ok")).await?;
    assert!(executor
        .resolve_incident_source_for_apply(wrong)
        .await?
        .is_none());

    // A stored network (not a single host) is never released.
    resolution(pool, "ip-pseudonym:net", "203.0.113.0/24", 600).await?;
    let net = starting(pool, block, target("ip-pseudonym:net")).await?;
    assert!(executor
        .resolve_incident_source_for_apply(net)
        .await?
        .is_none());

    // Unknown execution id.
    assert!(executor
        .resolve_incident_source_for_apply(Uuid::new_v4())
        .await?
        .is_none());

    // The executor has no direct read path to the table; other roles cannot call it.
    assert!(sqlx::query("SELECT raw_ip FROM security_ip_resolutions")
        .fetch_all(executor.pool())
        .await
        .is_err());
    assert!(
        sqlx::query("SELECT * FROM clawforge_resolve_incident_source_for_apply($1)")
            .bind(ok)
            .fetch_all(&api)
            .await
            .is_err(),
        "only the executor role may execute the resolver"
    );

    // Audit trail names the pseudonym but never the address.
    let rows: Vec<(String, Value)> = sqlx::query_as(
        "SELECT resource, details FROM audit_events WHERE action='incident_source_resolved_for_apply'",
    )
    .fetch_all(pool)
    .await?;
    assert!(rows.len() >= 10);
    let serialized = serde_json::to_string(&rows)?;
    assert!(!serialized.contains("203.0.113.50") && !serialized.contains("2001:db8"));
    assert!(rows.iter().any(|(resource, details)| {
        resource == &ok.to_string() && details["resolved"] == json!(true)
    }));
    Ok(())
}
