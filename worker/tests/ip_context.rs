//! The enrichment loop against a real database and a scripted lookup: only
//! targeted sources are asked, non-public addresses never are, Retry-After pauses
//! everything, failures keep good data and back off, results are verified by the
//! database, and the worker role needs nothing beyond its two functions.
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::Result;
use chrono::Utc;
use clawforge_intelligence::ip_context::{IpContextError, IpNetworkContext, RpkiSummary};
use clawforge_storage::PostgresStore;
use clawforge_worker::ip_context::{IpContextConfig, IpContextWorker, RoutingLookup};
use ipnet::IpNet;
use uuid::Uuid;

type Script = HashMap<IpAddr, Result<IpNetworkContext, IpContextError>>;

#[derive(Clone, Default)]
struct Scripted {
    answers: Arc<Mutex<Script>>,
    asked: Arc<Mutex<Vec<IpAddr>>>,
}

impl RoutingLookup for Scripted {
    async fn lookup(&self, ip: IpAddr) -> Result<IpNetworkContext, IpContextError> {
        self.asked.lock().unwrap().push(ip);
        match self.answers.lock().unwrap().get(&ip) {
            Some(Ok(context)) => Ok(context.clone()),
            Some(Err(IpContextError::RateLimited {
                retry_after_seconds,
            })) => Err(IpContextError::RateLimited {
                retry_after_seconds: *retry_after_seconds,
            }),
            Some(Err(IpContextError::Upstream(code))) => Err(IpContextError::Upstream(*code)),
            Some(Err(IpContextError::Transport)) => Err(IpContextError::Transport),
            Some(Err(IpContextError::Rejected(why))) => Err(IpContextError::Rejected(why)),
            None => Err(IpContextError::Transport),
        }
    }
}

fn context(prefix: Option<&str>, asns: &[u32], rpki: RpkiSummary) -> IpNetworkContext {
    IpNetworkContext {
        prefix: prefix.map(|p| p.parse::<IpNet>().unwrap()),
        origin_asns: asns.to_vec(),
        rpki,
        source: "ripestat".into(),
        fetched_at: Utc::now(),
    }
}

fn config() -> IpContextConfig {
    IpContextConfig {
        min_confidence: 60,
        assessment_max_age_seconds: 3600,
        batch: 10,
        ttl_seconds: 3600,
        spacing: Duration::from_millis(1),
        cycle: Duration::from_secs(60),
    }
}

async fn suspicious(owner: &PostgresStore, ip: &str, confidence: i16) -> Result<String> {
    let who = format!("ip-pseudonym:ctx-{}", Uuid::new_v4().simple());
    sqlx::query("INSERT INTO security_ip_resolutions(pseudonym,raw_ip,source,expires_at) VALUES($1,$2::inet,'ctx-test',NOW()+INTERVAL '1 hour')")
        .bind(&who).bind(ip).execute(owner.pool()).await?;
    sqlx::query("INSERT INTO security_assessments(id,rule_id,rule_version,engine_version,dedupe_key,resource,severity,confidence,summary,event_count,window_seconds,bucket_start,first_seen,last_seen) VALUES($1,'ssh_bruteforce','2','t',$2,$3,'high',$4,'s',5,300,NOW(),NOW(),NOW())")
        .bind(Uuid::new_v4()).bind(format!("t-{}", Uuid::new_v4())).bind(&who).bind(confidence)
        .execute(owner.pool()).await?;
    Ok(who)
}

fn octets() -> (u8, u8) {
    let n = Uuid::new_v4().as_u128();
    ((n % 200) as u8 + 1, ((n >> 8) % 250) as u8 + 1)
}

#[tokio::test]
#[ignore = "requires a provisioned isolated PostgreSQL database with the worker role"]
async fn the_loop_enriches_targeted_public_sources_politely_and_safely() -> Result<()> {
    let owner = PostgresStore::connect(&std::env::var("CLAWFORGE_TEST_DATABASE_URL")?).await?;
    let worker_store =
        PostgresStore::connect_runtime(&std::env::var("CLAWFORGE_TEST_WORKER_DATABASE_URL")?)
            .await?;
    let (a, b) = octets();
    // Public-looking addresses that are unique per run; the lookup is scripted.
    let routed_ip: IpAddr = format!("45.{a}.{b}.7").parse()?;
    let unrouted_ip: IpAddr = format!("46.{a}.{b}.7").parse()?;
    let flaky_ip: IpAddr = format!("47.{a}.{b}.7").parse()?;
    let rejected_ip: IpAddr = format!("48.{a}.{b}.7").parse()?;
    let wrong_ip: IpAddr = format!("49.{a}.{b}.7").parse()?;
    let private_ip = format!("10.{a}.{b}.7");
    let quiet_ip: IpAddr = format!("50.{a}.{b}.7").parse()?;

    let routed = suspicious(&owner, &routed_ip.to_string(), 90).await?;
    let unrouted = suspicious(&owner, &unrouted_ip.to_string(), 90).await?;
    let flaky = suspicious(&owner, &flaky_ip.to_string(), 90).await?;
    let rejected = suspicious(&owner, &rejected_ip.to_string(), 90).await?;
    let wrong = suspicious(&owner, &wrong_ip.to_string(), 90).await?;
    let private = suspicious(&owner, &private_ip, 90).await?;
    let quiet = suspicious(&owner, &quiet_ip.to_string(), 20).await?; // below the confidence floor

    let scripted = Scripted::default();
    {
        let mut answers = scripted.answers.lock().unwrap();
        answers.insert(
            routed_ip,
            Ok(context(
                Some(&format!("45.{a}.{b}.0/24")),
                &[64496],
                RpkiSummary::Valid,
            )),
        );
        answers.insert(unrouted_ip, Ok(context(None, &[], RpkiSummary::NotChecked)));
        answers.insert(flaky_ip, Err(IpContextError::Upstream(503)));
        answers.insert(rejected_ip, Err(IpContextError::Rejected("hostile body")));
        // A lookup claiming a prefix that does not contain the address: the database refuses it.
        answers.insert(
            wrong_ip,
            Ok(context(Some("9.9.9.0/24"), &[64500], RpkiSummary::Valid)),
        );
    }
    let mut worker = IpContextWorker::new(worker_store, scripted.clone(), config());
    let start = Instant::now();
    let report = worker.run_cycle(start).await?;
    assert_eq!(report.routed, 1, "{report:?}");
    assert_eq!(report.unrouted, 1);
    assert_eq!(report.failed, 2);
    assert_eq!(report.refused_by_database, 1);
    assert_eq!(report.skipped_non_public, 1);
    assert!(!report.rate_limited && !report.paused);

    let asked = scripted.asked.lock().unwrap().clone();
    assert!(
        !asked.iter().any(|ip| ip.to_string() == private_ip),
        "a private address never leaves the host"
    );
    assert!(
        !asked.contains(&quiet_ip),
        "a source below the confidence floor is not worth a third-party request"
    );

    let ctx = owner
        .current_source_intel(&routed)
        .await?
        .context
        .expect("stored");
    assert_eq!((ctx.origin_asns, ctx.rpki.as_str()), (vec![64496], "valid"));
    assert!(
        owner.current_source_intel(&wrong).await?.context.is_none(),
        "refused result stores nothing"
    );
    assert!(owner.current_source_intel(&flaky).await?.context.is_none());
    let _ = (&unrouted, &rejected, &private, &quiet);

    // Second cycle: nothing new is targeted - fresh context, skipped and backed-off sources wait.
    let before = scripted.asked.lock().unwrap().len();
    let again = worker.run_cycle(start + Duration::from_secs(1)).await?;
    assert_eq!(again.targets, 0, "{again:?}");
    assert_eq!(scripted.asked.lock().unwrap().len(), before);
    Ok(())
}

#[tokio::test]
#[ignore = "requires a provisioned isolated PostgreSQL database with the worker role"]
async fn retry_after_pauses_the_whole_loop_and_the_source() -> Result<()> {
    let owner = PostgresStore::connect(&std::env::var("CLAWFORGE_TEST_DATABASE_URL")?).await?;
    let worker_store =
        PostgresStore::connect_runtime(&std::env::var("CLAWFORGE_TEST_WORKER_DATABASE_URL")?)
            .await?;
    let (a, b) = octets();
    let first: IpAddr = format!("51.{a}.{b}.7").parse()?;
    let second: IpAddr = format!("52.{a}.{b}.7").parse()?;
    let limited = suspicious(&owner, &first.to_string(), 99).await?;
    let waiting = suspicious(&owner, &second.to_string(), 95).await?;
    let scripted = Scripted::default();
    scripted.answers.lock().unwrap().insert(
        first,
        Err(IpContextError::RateLimited {
            retry_after_seconds: 120,
        }),
    );
    scripted.answers.lock().unwrap().insert(
        second,
        Ok(context(
            Some(&format!("52.{a}.{b}.0/24")),
            &[64497],
            RpkiSummary::Unknown,
        )),
    );
    let mut worker = IpContextWorker::new(worker_store, scripted.clone(), config());
    let start = Instant::now();

    let report = worker.run_cycle(start).await?;
    assert!(report.rate_limited && report.failed == 1, "{report:?}");
    assert_eq!(
        scripted.asked.lock().unwrap().len(),
        1,
        "the loop stops at the first 429"
    );
    // The source is not retried before Retry-After; it is recorded with that wait.
    let wait: f64 = sqlx::query_scalar("SELECT EXTRACT(EPOCH FROM (next_attempt_at-NOW()))::float8 FROM source_network_context WHERE pseudonym=$1")
        .bind(&limited).fetch_one(owner.pool()).await?;
    assert!(
        wait > 100.0,
        "Retry-After honoured in the database, got {wait}"
    );

    // During the pause nothing is even listed or asked.
    let paused = worker.run_cycle(start + Duration::from_secs(30)).await?;
    assert!(paused.paused && paused.targets == 0);
    assert_eq!(scripted.asked.lock().unwrap().len(), 1);

    // After the pause the other source is served; the limited one still waits in the database.
    let resumed = worker.run_cycle(start + Duration::from_secs(121)).await?;
    assert_eq!(resumed.routed, 1, "{resumed:?}");
    assert!(owner
        .current_source_intel(&waiting)
        .await?
        .context
        .is_some());
    assert!(
        !scripted
            .asked
            .lock()
            .unwrap()
            .iter()
            .skip(1)
            .any(|ip| *ip == first),
        "the limited source is not asked again early"
    );
    Ok(())
}
