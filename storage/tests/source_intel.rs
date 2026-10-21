//! Current source intelligence (migration 0063): feed additions, removals and
//! expiry are seen at once; ASN reputation needs routing context; routing facts
//! alone never make a source "listed"; the worker's record path re-verifies what
//! the database can; roles are least-privilege.
use anyhow::Result;
use chrono::Utc;
use clawforge_storage::{NetworkContextOutcome, PostgresStore};
use sqlx::PgPool;
use uuid::Uuid;

async fn store() -> Result<PostgresStore> {
    PostgresStore::connect(&std::env::var("CLAWFORGE_TEST_DATABASE_URL")?).await
}

fn pseudonym() -> String {
    format!("ip-pseudonym:intel-{}", Uuid::new_v4().simple())
}

/// A documentation-range address unique to this test run.
fn address() -> String {
    format!("203.0.113.{}", Uuid::new_v4().as_u128() % 200 + 20)
}

async fn resolve(pool: &PgPool, pseudonym: &str, ip: &str, ttl_seconds: i64) -> Result<()> {
    sqlx::query("INSERT INTO security_ip_resolutions(pseudonym,raw_ip,source,expires_at) VALUES($1,$2::inet,'intel-test',NOW()+($3*INTERVAL '1 second'))")
        .bind(pseudonym).bind(ip).bind(ttl_seconds).execute(pool).await?;
    Ok(())
}

async fn indicator(
    pool: &PgPool,
    value: &str,
    kind: &str,
    category: &str,
    source: &str,
    confidence: i16,
    expires_in_seconds: i64,
) -> Result<i64> {
    Ok(sqlx::query_scalar(
        "INSERT INTO indicators (value,indicator_type,categories,confidence,source,first_seen,last_seen,expires_at) \
         VALUES ($1,$2,jsonb_build_array($3::text),$4,$5,NOW(),NOW(),NOW()+($6*INTERVAL '1 second')) RETURNING id",
    )
    .bind(value).bind(kind).bind(category).bind(confidence).bind(source).bind(expires_in_seconds)
    .fetch_one(pool).await?)
}

async fn routed(
    store: &PostgresStore,
    pseudonym: &str,
    prefix: &str,
    asns: &[i64],
    rpki: &str,
) -> Result<bool> {
    store
        .record_network_context(
            pseudonym,
            &NetworkContextOutcome::Routed {
                prefix: prefix.into(),
                origin_asns: asns.to_vec(),
                rpki: rpki.into(),
                ttl_seconds: 3600,
            },
        )
        .await
}

#[tokio::test]
#[ignore = "requires a provisioned isolated PostgreSQL database"]
async fn feed_additions_removals_and_expiry_are_seen_at_once() -> Result<()> {
    let store = store().await?;
    let pool = store.pool();
    let who = pseudonym();
    let ip = address();
    let tag = Uuid::new_v4().simple().to_string();

    // No resolution: there is no current view, which is not "not listed".
    let none = store.current_source_intel(&who).await?;
    assert!(!none.resolved && none.ip.is_none() && none.asn.is_none() && none.context.is_none());

    resolve(pool, &who, &ip, 3600).await?;
    let clean = store.current_source_intel(&who).await?;
    assert!(clean.resolved && clean.ip.is_none());

    // Listed AFTER the events were recorded: visible immediately.
    let id = indicator(
        pool,
        "203.0.113.0/24",
        "Prefix",
        "spamhaus_drop",
        &format!("feed-{tag}"),
        85,
        3600,
    )
    .await?;
    let listed = store.current_source_intel(&who).await?;
    let hit = listed.ip.expect("a later listing is seen");
    assert_eq!(
        (hit.source.as_str(), hit.confidence),
        (format!("feed-{tag}").as_str(), 85)
    );
    assert!(hit.is_usable(50, 3600, Utc::now()));
    assert!(!hit.is_usable(90, 3600, Utc::now()), "confidence floor");
    assert!(
        !hit.is_usable(50, 3600, Utc::now() + chrono::Duration::hours(2)),
        "staleness"
    );

    // Removed from the feed: gone at once.
    sqlx::query("DELETE FROM indicators WHERE id=$1")
        .bind(id)
        .execute(pool)
        .await?;
    assert!(store.current_source_intel(&who).await?.ip.is_none());

    // Expired: not listed. Network-context rows and default routes: never listed.
    let expired = indicator(
        pool,
        "203.0.113.0/24",
        "Prefix",
        "spamhaus_drop",
        &format!("old-{tag}"),
        90,
        -5,
    )
    .await?;
    let ctx = indicator(
        pool,
        "203.0.113.0/24",
        "Prefix",
        "network-intelligence",
        &format!("ctx-{tag}"),
        99,
        3600,
    )
    .await?;
    let wide = indicator(
        pool,
        "0.0.0.0/0",
        "Prefix",
        "spamhaus_drop",
        &format!("wide-{tag}"),
        99,
        3600,
    )
    .await?;
    let single = indicator(
        pool,
        &ip,
        "Ip",
        "feodo_tracker",
        &format!("single-{tag}"),
        70,
        3600,
    )
    .await?;
    let one = store.current_source_intel(&who).await?;
    assert_eq!(
        one.ip.as_ref().map(|h| h.source.clone()),
        Some(format!("single-{tag}"))
    );
    sqlx::query("DELETE FROM indicators WHERE id = ANY($1)")
        .bind(vec![expired, ctx, wide, single])
        .execute(pool)
        .await?;

    // The resolution itself expiring ends the current view.
    sqlx::query("UPDATE security_ip_resolutions SET expires_at=NOW()-INTERVAL '1 second' WHERE pseudonym=$1")
        .bind(&who).execute(pool).await?;
    assert!(!store.current_source_intel(&who).await?.resolved);
    Ok(())
}

#[tokio::test]
#[ignore = "requires a provisioned isolated PostgreSQL database"]
async fn asn_reputation_needs_context_and_routing_alone_never_lists_a_source() -> Result<()> {
    let store = store().await?;
    let pool = store.pool();
    let who = pseudonym();
    let ip = address();
    let tag = Uuid::new_v4().simple().to_string();
    let asn: i64 = 4_200_000_000 + (Uuid::new_v4().as_u128() % 90_000_000) as i64;
    resolve(pool, &who, &ip, 3600).await?;

    // An ASN-DROP style listing without routing context cannot apply to anything.
    let listing = indicator(
        pool,
        &format!("AS{asn}"),
        "Asn",
        "spamhaus_asn",
        &format!("asn-{tag}"),
        80,
        3600,
    )
    .await?;
    assert!(store.current_source_intel(&who).await?.asn.is_none());

    // Routing context alone (even an RPKI-invalid, multi-origin one) lists nothing.
    assert!(routed(&store, &who, "203.0.113.0/24", &[asn, asn + 1], "invalid").await?);
    let without_listing_for_second = store.current_source_intel(&who).await?;
    let found = without_listing_for_second
        .asn
        .expect("the listed origin ASN is found");
    assert_eq!(found.asn, asn);
    assert_eq!(
        without_listing_for_second.context.as_ref().unwrap().rpki,
        "invalid"
    );
    assert_eq!(
        without_listing_for_second
            .context
            .as_ref()
            .unwrap()
            .origin_asns,
        vec![asn, asn + 1]
    );
    assert!(
        without_listing_for_second.ip.is_none(),
        "an ASN listing is not an address listing"
    );

    // Context-provider ASN rows (HackerTarget, PeeringDB, ...) never count as reputation.
    sqlx::query("DELETE FROM indicators WHERE id=$1")
        .bind(listing)
        .execute(pool)
        .await?;
    let provider_row = indicator(
        pool,
        &format!("AS{asn}"),
        "Asn",
        "network-intelligence",
        &format!("peeringdb-{tag}"),
        99,
        3600,
    )
    .await?;
    let only_context = store.current_source_intel(&who).await?;
    assert!(only_context.asn.is_none() && only_context.ip.is_none());
    assert!(
        only_context.context.is_some(),
        "the routing facts are still reported"
    );
    sqlx::query("DELETE FROM indicators WHERE id=$1")
        .bind(provider_row)
        .execute(pool)
        .await?;

    // The qualifying listing prefers the address over its ASN.
    let both_asn = indicator(
        pool,
        &format!("AS{}", asn + 1),
        "Asn",
        "spamhaus_asn",
        &format!("asn2-{tag}"),
        90,
        3600,
    )
    .await?;
    let both_ip = indicator(
        pool,
        "203.0.113.0/24",
        "Prefix",
        "spamhaus_drop",
        &format!("ip2-{tag}"),
        60,
        3600,
    )
    .await?;
    let intel = store.current_source_intel(&who).await?;
    let (basis, _) = intel.qualifying_listing(50, 3600, Utc::now()).unwrap();
    assert_eq!(basis, "ip");
    sqlx::query("DELETE FROM indicators WHERE id = ANY($1)")
        .bind(vec![both_asn, both_ip])
        .execute(pool)
        .await?;

    // BGP anomaly only counts when anomalous, recent, specific and covering the address.
    for (prefix, status, age_hours, expect) in [
        ("203.0.113.0/24", "Anomalous", 1, true),
        ("203.0.113.0/24", "Unknown", 1, false),
        ("203.0.113.0/24", "Anomalous", 48, false),
        ("0.0.0.0/0", "Anomalous", 1, false),
        ("198.51.100.0/24", "Anomalous", 1, false),
    ] {
        let id: i64 = sqlx::query_scalar(
            "INSERT INTO bgp_events (prefix,origin_asn,status,rpki_status,first_seen,last_seen,fingerprint) \
             VALUES ($1,'AS64496',$2,'Unknown',NOW(),NOW()-($3*INTERVAL '1 hour'),$4) RETURNING id",
        )
        .bind(prefix).bind(status).bind(age_hours).bind(format!("fp-{}", Uuid::new_v4()))
        .fetch_one(pool).await?;
        let seen = store.current_source_intel(&who).await?.bgp_anomaly;
        sqlx::query("DELETE FROM bgp_events WHERE id=$1")
            .bind(id)
            .execute(pool)
            .await?;
        assert_eq!(seen, expect, "{prefix} {status} {age_hours}h");
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires a provisioned isolated PostgreSQL database"]
async fn recording_context_is_re_verified_by_the_database() -> Result<()> {
    let store = store().await?;
    let pool = store.pool();
    let ip = address();
    let who = pseudonym();

    // No live resolution: refused.
    assert!(!routed(&store, &who, "203.0.113.0/24", &[64496], "valid").await?);
    resolve(pool, &who, &ip, 120).await?;

    // A prefix that does not contain the address, a default-route-wide prefix, bad
    // ASN lists and an unknown RPKI word are refused; nothing is stored.
    for (prefix, asns, rpki) in [
        ("198.51.100.0/24", vec![64496_i64], "valid"),
        ("0.0.0.0/0", vec![64496], "valid"),
        ("203.0.113.0/24", vec![], "valid"),
        ("203.0.113.0/24", vec![0], "valid"),
        ("203.0.113.0/24", vec![4_294_967_296], "valid"),
        ("203.0.113.0/24", (1..=17).collect(), "valid"),
        ("203.0.113.0/24", vec![64496], "definitely"),
    ] {
        assert!(
            !routed(&store, &who, prefix, &asns, rpki).await?,
            "{prefix} {asns:?} {rpki}"
        );
    }
    assert!(store.current_source_intel(&who).await?.context.is_none());
    let bad_ttl = store
        .record_network_context(&who, &NetworkContextOutcome::Unrouted { ttl_seconds: 59 })
        .await?;
    assert!(!bad_ttl);

    // Valid: stored, and the context cannot outlive the resolution (120 s < 3600 s ttl).
    assert!(routed(&store, &who, "203.0.113.0/24", &[64496], "valid").await?);
    let ctx = store
        .current_source_intel(&who)
        .await?
        .context
        .expect("stored");
    assert_eq!(
        (ctx.prefix.as_str(), ctx.rpki.as_str()),
        ("203.0.113.0/24", "valid")
    );
    let remaining: f64 = sqlx::query_scalar("SELECT EXTRACT(EPOCH FROM (expires_at-NOW()))::float8 FROM source_network_context WHERE pseudonym=$1")
        .bind(&who).fetch_one(pool).await?;
    assert!(
        remaining > 0.0 && remaining <= 121.0,
        "bounded by the resolution, got {remaining}"
    );

    // A failure keeps the good context and schedules a later attempt, honouring Retry-After.
    assert!(
        store
            .record_network_context(
                &who,
                &NetworkContextOutcome::Failed {
                    retry_after_seconds: 900,
                    error: "rate_limited".into()
                }
            )
            .await?
    );
    let (status, attempts, wait): (String, i32, f64) = sqlx::query_as("SELECT status, attempts, EXTRACT(EPOCH FROM (next_attempt_at-NOW()))::float8 FROM source_network_context WHERE pseudonym=$1")
        .bind(&who).fetch_one(pool).await?;
    assert_eq!((status.as_str(), attempts), ("ok", 1));
    assert!(wait > 800.0, "Retry-After honoured, got {wait}");
    assert!(
        store.current_source_intel(&who).await?.context.is_some(),
        "good data survives a failed refresh"
    );
    // Backoff grows with repeated failures and is capped.
    for _ in 0..12 {
        store
            .record_network_context(
                &who,
                &NetworkContextOutcome::Failed {
                    retry_after_seconds: 0,
                    error: "upstream_503".into(),
                },
            )
            .await?;
    }
    let wait: f64 = sqlx::query_scalar("SELECT EXTRACT(EPOCH FROM (next_attempt_at-NOW()))::float8 FROM source_network_context WHERE pseudonym=$1")
        .bind(&who).fetch_one(pool).await?;
    assert!(
        wait > 3000.0 && wait <= 3601.0,
        "capped exponential backoff, got {wait}"
    );
    // Error codes are short lowercase text, never a pasted response.
    assert!(store
        .record_network_context(
            &who,
            &NetworkContextOutcome::Failed {
                retry_after_seconds: 0,
                error: "{\"x\":1}".into()
            }
        )
        .await
        .is_err());

    // A brand-new source whose first attempt fails has no usable context.
    let fresh = pseudonym();
    resolve(pool, &fresh, &address(), 600).await?;
    assert!(
        store
            .record_network_context(
                &fresh,
                &NetworkContextOutcome::Failed {
                    retry_after_seconds: 5,
                    error: "transport".into()
                }
            )
            .await?
    );
    assert!(store.current_source_intel(&fresh).await?.context.is_none());
    Ok(())
}

#[tokio::test]
#[ignore = "requires a provisioned isolated PostgreSQL database"]
async fn only_suspicious_sources_without_fresh_context_are_targeted_and_roles_are_least_privilege(
) -> Result<()> {
    let store = store().await?;
    let pool = store.pool();
    let (hot, hot_ip) = (pseudonym(), address());
    let (quiet, quiet_ip) = (pseudonym(), address());
    let (stale, stale_ip) = (pseudonym(), address());
    let (done, done_ip) = (pseudonym(), address());
    let (waiting, waiting_ip) = (pseudonym(), address());
    for (who, ip, confidence, last_seen_age) in [
        (&hot, &hot_ip, 90_i16, 0_i64),
        (&quiet, &quiet_ip, 30, 0),
        (&stale, &stale_ip, 90, 7200),
        (&done, &done_ip, 90, 0),
        (&waiting, &waiting_ip, 90, 0),
    ] {
        resolve(pool, who, ip, 3600).await?;
        sqlx::query("INSERT INTO security_assessments(id,rule_id,rule_version,engine_version,dedupe_key,resource,severity,confidence,summary,event_count,window_seconds,bucket_start,first_seen,last_seen) VALUES($1,'ssh_bruteforce','2','t',$2,$3,'high',$4,'s',5,300,NOW(),NOW(),NOW()-($5*INTERVAL '1 second'))")
            .bind(Uuid::new_v4()).bind(format!("t-{}", Uuid::new_v4())).bind(who).bind(confidence).bind(last_seen_age)
            .execute(pool).await?;
    }
    let done_prefix = format!("{}.0/24", done_ip.rsplit_once('.').unwrap().0);
    assert!(routed(&store, &done, &done_prefix, &[64496], "valid").await?);
    assert!(
        store
            .record_network_context(
                &waiting,
                &NetworkContextOutcome::Failed {
                    retry_after_seconds: 600,
                    error: "transport".into()
                }
            )
            .await?
    );

    let targets = store.network_context_targets(50, 3600, 60).await?;
    let names: Vec<&str> = targets.iter().map(|t| t.pseudonym.as_str()).collect();
    assert!(
        names.contains(&hot.as_str()),
        "recent, confident, no context"
    );
    for excluded in [&quiet, &stale, &done, &waiting] {
        assert!(
            !names.contains(&excluded.as_str()),
            "{excluded} must not be targeted"
        );
    }
    let hot_target = targets.iter().find(|t| t.pseudonym == hot).unwrap();
    assert_eq!(hot_target.raw_ip, hot_ip);
    assert!(
        !format!("{hot_target:?}").contains(&hot_ip),
        "Debug must not leak the address"
    );
    // Bounds: limit capped at 50, parameters range-checked.
    assert!(store.network_context_targets(1000, 3600, 60).await?.len() <= 50);
    assert!(store.network_context_targets(10, 5, 60).await?.is_empty());
    assert!(store.network_context_targets(10, 3600, 0).await?.is_empty());
    assert!(store.network_context_targets(0, 3600, 60).await?.is_empty());

    // Least privilege: the worker lists and records; the policy engine reads the view;
    // nobody else (not even the API role) may execute any of the three.
    for (role, function, allowed) in [
        ("clawforge_worker", "clawforge_network_context_targets(integer,integer,integer)", true),
        ("clawforge_worker", "clawforge_record_network_context(text,text,cidr,bigint[],text,text,integer,integer,text)", true),
        ("clawforge_worker", "clawforge_current_source_intel(text)", false),
        ("clawforge_policy_engine", "clawforge_current_source_intel(text)", true),
        ("clawforge_policy_engine", "clawforge_network_context_targets(integer,integer,integer)", false),
        ("clawforge_policy_engine", "clawforge_record_network_context(text,text,cidr,bigint[],text,text,integer,integer,text)", false),
        ("clawforge_api", "clawforge_network_context_targets(integer,integer,integer)", false),
        ("clawforge_api", "clawforge_current_source_intel(text)", false),
        ("clawforge_executor", "clawforge_network_context_targets(integer,integer,integer)", false),
        ("clawforge_security_engine", "clawforge_current_source_intel(text)", false),
    ] {
        let can: bool = sqlx::query_scalar("SELECT has_function_privilege($1, $2, 'EXECUTE')")
            .bind(role).bind(function).fetch_one(pool).await?;
        assert_eq!(can, allowed, "{role} on {function}");
    }
    // The context table is written through the worker's verified function only. The API
    // role may read it (public routing facts, no addresses) but never write it.
    for role in [
        "clawforge_worker",
        "clawforge_policy_engine",
        "clawforge_executor",
        "clawforge_security_engine",
    ] {
        let can: bool = sqlx::query_scalar("SELECT has_table_privilege($1, 'source_network_context', 'SELECT,INSERT,UPDATE,DELETE')")
            .bind(role).fetch_one(pool).await?;
        assert!(!can, "{role} must have no direct table access");
    }
    let read: bool = sqlx::query_scalar(
        "SELECT has_table_privilege('clawforge_api', 'source_network_context', 'SELECT')",
    )
    .fetch_one(pool)
    .await?;
    let write: bool = sqlx::query_scalar("SELECT has_table_privilege('clawforge_api', 'source_network_context', 'INSERT,UPDATE,DELETE')")
        .fetch_one(pool).await?;
    assert!(read && !write, "api: read yes, write no");
    Ok(())
}
