//! Staggered-window detection (rule version 2) and the HTTP status-class split.
//! Pure properties run everywhere; the PostgreSQL tests run in the isolated CI
//! fixture as the least-privilege `security_engine` role.
use super::*;

fn t(h: u32, m: u32, s: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 3, 1, h, m, s).unwrap()
}

#[test]
fn offset_grids_are_disjoint_in_start_and_deterministic() {
    for window in [300_i64, 60, 3600] {
        let [a, b] = grid_offsets(window);
        assert_eq!((a, b), (0, window / 2));
        for sec in (0..4 * window).step_by(7) {
            let at = Utc.timestamp_opt(1_800_000_000 + sec, 0).unwrap();
            let primary = bucket_start(at, window, a);
            let shifted = bucket_start(at, window, b);
            assert_ne!(primary, shifted, "the two grids can never share a start");
            assert_eq!(primary.timestamp().rem_euclid(window), 0);
            assert_eq!(shifted.timestamp().rem_euclid(window), b);
            assert!(primary <= at && at < primary + Duration::seconds(window));
            assert!(shifted <= at && at < shifted + Duration::seconds(window));
        }
    }
}

/// The guarantee stated in the engine docs: any span of at most half a window
/// lies entirely inside one window of one grid; longer spans may not.
#[test]
fn any_span_up_to_half_a_window_is_covered_by_one_window_of_one_grid() {
    let window = 300;
    let covered = |start: i64, span: i64| {
        let first = Utc.timestamp_opt(start, 0).unwrap();
        let last = Utc.timestamp_opt(start + span, 0).unwrap();
        grid_offsets(window).iter().any(|offset| {
            bucket_start(first, window, *offset) == bucket_start(last, window, *offset)
        })
    };
    for start in 0..600 {
        for span in 0..=150 {
            assert!(
                covered(start, span),
                "span {span} from {start} must be covered"
            );
        }
    }
    // Honest limit: a span of a full window can fall between both grids.
    assert!((0..600).any(|start| !covered(start, 300)));
}

#[test]
fn the_exact_boundary_instant_belongs_to_the_later_window() {
    let boundary = t(12, 5, 0);
    assert_eq!(bucket_start(boundary, 300, 0), boundary);
    assert_eq!(
        bucket_start(boundary - Duration::seconds(1), 300, 0),
        boundary - Duration::seconds(300)
    );
    assert_eq!(
        bucket_start(boundary, 300, 150),
        boundary - Duration::seconds(150)
    );
    assert_eq!(
        bucket_start(boundary + Duration::seconds(149), 300, 150),
        boundary - Duration::seconds(150)
    );
    assert_eq!(
        bucket_start(boundary + Duration::seconds(150), 300, 150),
        boundary + Duration::seconds(150)
    );
}

fn url(role: &str) -> Result<String> {
    Ok(env::var(format!(
        "CLAWFORGE_TEST_{}_DATABASE_URL",
        role.to_ascii_uppercase()
    ))?)
}

struct Fixture {
    owner: PostgresStore,
    engine: PostgresStore,
    incidents: PostgresStore,
    resource: String,
    serial: u32,
}

impl Fixture {
    async fn new() -> Result<Self> {
        Ok(Self {
            owner: PostgresStore::connect_runtime(&env::var("CLAWFORGE_TEST_DATABASE_URL")?)
                .await?,
            engine: PostgresStore::connect_runtime(&url("security_engine")?).await?,
            incidents: PostgresStore::connect_runtime(&url("incidents")?).await?,
            resource: format!("ip-pseudonym:window-{}", Uuid::new_v4()),
            serial: 0,
        })
    }

    async fn event(
        &mut self,
        event_type: &str,
        at: DateTime<Utc>,
        payload: serde_json::Value,
    ) -> Result<EventRecord> {
        self.serial += 1;
        self.owner
            .publish_event(
                event_type,
                "test-sensor",
                "low",
                at,
                Some(&self.resource),
                payload,
                serde_json::json!({}),
                &format!("window-test:{}:{}", self.resource, self.serial),
            )
            .await?;
        Ok(EventRecord {
            event_type: event_type.into(),
            occurred_at: at,
            correlation_id: Some(self.resource.clone()),
        })
    }

    async fn ssh(&mut self, at: DateTime<Utc>) -> Result<EventRecord> {
        self.event(
            "ssh_login_failure",
            at,
            serde_json::json!({"username": "u"}),
        )
        .await
    }

    async fn http(&mut self, at: DateTime<Utc>, path: &str, status: u16) -> Result<EventRecord> {
        self.event(
            "http_anomaly",
            at,
            serde_json::json!({"path": path, "status_code": status}),
        )
        .await
    }

    /// `(rule_id, bucket_start, event_count)` of this resource's assessments.
    async fn assessments(&self) -> Result<Vec<(String, DateTime<Utc>, i32)>> {
        Ok(sqlx::query_as(
            "SELECT rule_id, bucket_start, event_count FROM security_assessments \
             WHERE resource=$1 ORDER BY rule_id, bucket_start",
        )
        .bind(&self.resource)
        .fetch_all(self.owner.pool())
        .await?)
    }

    async fn candidates(&self) -> Result<i64> {
        Ok(sqlx::query_scalar(
            "SELECT count(*) FROM incident_candidates WHERE correlation_key LIKE $1",
        )
        .bind(format!("security-assessment:%:{}", self.resource))
        .fetch_one(self.owner.pool())
        .await?)
    }

    async fn run_ssh(&self, event: &EventRecord) -> Result<()> {
        evaluate_rule(&self.engine, &SSH_BRUTEFORCE, event).await
    }

    /// Leave no open candidate for later tests that count promotions.
    async fn finish(&self) -> Result<()> {
        self.incidents.promote_incident_candidates(100).await?;
        Ok(())
    }
}

/// Four SSH failures on each side of a bucket boundary used to evade the
/// threshold of five. Delivered out of order and replayed, the result must be
/// exactly one assessment on the shifted grid and one incident candidate.
#[tokio::test]
#[ignore = "requires provisioned roles in an isolated PostgreSQL test container"]
async fn ssh_four_plus_four_across_a_boundary_is_detected_once_and_replay_safe() -> Result<()> {
    let mut f = Fixture::new().await?;
    let boundary = t(12, 5, 0);
    let mut events = Vec::new();
    for second in [-4, -3, -2, -1, 0, 1, 2, 3] {
        events.push(f.ssh(boundary + Duration::seconds(second)).await?);
    }
    // Out-of-order delivery: newest first, then the oldest, then the middle.
    for index in [7, 0, 6, 1, 5, 2, 4, 3] {
        f.run_ssh(&events[index]).await?;
    }
    let found = f.assessments().await?;
    assert_eq!(
        found,
        vec![(
            "ssh_bruteforce".to_string(),
            boundary - Duration::seconds(150),
            8
        )],
        "no primary-grid assessment (4 + 4), exactly one shifted-grid assessment"
    );
    let dedupe: String =
        sqlx::query_scalar("SELECT dedupe_key FROM security_assessments WHERE resource=$1")
            .bind(&f.resource)
            .fetch_one(f.owner.pool())
            .await?;
    assert!(dedupe.starts_with("ssh_bruteforce:v2:"), "{dedupe}");
    assert_eq!(f.candidates().await?, 1);

    // Replays and an old event again: nothing changes.
    for index in [0, 7, 3, 3] {
        f.run_ssh(&events[index]).await?;
    }
    assert_eq!(f.assessments().await?, found);
    assert_eq!(f.candidates().await?, 1);
    f.finish().await
}

#[tokio::test]
#[ignore = "requires provisioned roles in an isolated PostgreSQL test container"]
async fn ssh_threshold_edges_across_a_boundary() -> Result<()> {
    let boundary = t(13, 10, 0);
    // (before, after, fires)
    for (before, after, fires) in [
        (2, 2, false),
        (3, 1, false),
        (4, 0, false),
        (3, 2, true),
        (1, 4, true),
        (5, 0, true),
    ] {
        let mut f = Fixture::new().await?;
        let mut events = Vec::new();
        for i in 0..before {
            events.push(f.ssh(boundary - Duration::seconds(1 + i)).await?);
        }
        for i in 0..after {
            events.push(f.ssh(boundary + Duration::seconds(i)).await?);
        }
        for event in &events {
            f.run_ssh(event).await?;
        }
        let found = f.assessments().await?;
        assert_eq!(!found.is_empty(), fires, "{before}+{after}: {found:?}");
        assert!(
            found
                .iter()
                .all(|(_, _, count)| *count == (before + after) as i32),
            "{found:?}"
        );
        f.finish().await?;
    }
    Ok(())
}

/// A spread of a whole window can still fall between both grids; that is the
/// documented limit (fewer than the threshold in any window of either grid).
#[tokio::test]
#[ignore = "requires provisioned roles in an isolated PostgreSQL test container"]
async fn ssh_spread_over_a_full_window_is_not_claimed_to_be_detected() -> Result<()> {
    let mut f = Fixture::new().await?;
    let boundary = t(14, 0, 0);
    let mut events = Vec::new();
    for i in 0..4 {
        events.push(f.ssh(boundary - Duration::seconds(140 + i)).await?);
    }
    for i in 0..4 {
        events.push(f.ssh(boundary + Duration::seconds(160 + i)).await?);
    }
    for event in &events {
        f.run_ssh(event).await?;
    }
    assert!(f.assessments().await?.is_empty());
    f.finish().await
}

#[tokio::test]
#[ignore = "requires provisioned roles in an isolated PostgreSQL test container"]
async fn http_scan_seven_plus_seven_paths_across_a_boundary_is_detected() -> Result<()> {
    let mut f = Fixture::new().await?;
    let boundary = t(15, 20, 0);
    let mut events = Vec::new();
    for i in 0..7 {
        events.push(
            f.http(
                boundary - Duration::seconds(7 - i),
                &format!("/probe-{i}"),
                404,
            )
            .await?,
        );
    }
    for i in 0..7 {
        events.push(
            f.http(
                boundary + Duration::seconds(i),
                &format!("/probe-{}", 7 + i),
                404,
            )
            .await?,
        );
    }
    for event in events.iter().rev() {
        evaluate_scan_rule(&f.engine, &HTTP_SCAN, event).await?;
        evaluate_rule(&f.engine, &HTTP_ANOMALY_BURST, event).await?;
    }
    let found = f.assessments().await?;
    let scan: Vec<_> = found
        .iter()
        .filter(|(rule, _, _)| rule == "http_scan")
        .collect();
    assert_eq!(scan.len(), 1, "{found:?}");
    assert_eq!(scan[0].1, boundary - Duration::seconds(150));
    assert_eq!(scan[0].2, 14);
    // The same 14 events also trip the burst rule on the shifted grid, as one
    // observation: both rules share one event family and one incident each.
    assert!(found
        .iter()
        .any(|(rule, _, _)| rule == "http_anomaly_burst"));
    // Replay: unchanged.
    for event in &events {
        evaluate_scan_rule(&f.engine, &HTTP_SCAN, event).await?;
    }
    assert_eq!(f.assessments().await?, found);
    f.finish().await
}

#[tokio::test]
#[ignore = "requires provisioned roles in an isolated PostgreSQL test container"]
async fn http_scan_just_below_the_distinct_threshold_across_a_boundary_stays_quiet() -> Result<()> {
    let mut f = Fixture::new().await?;
    let boundary = t(16, 30, 0);
    let mut events = Vec::new();
    for i in 0..4 {
        events.push(
            f.http(boundary - Duration::seconds(4 - i), &format!("/p{i}"), 404)
                .await?,
        );
    }
    for i in 0..3 {
        events.push(
            f.http(
                boundary + Duration::seconds(i),
                &format!("/p{}", 4 + i),
                404,
            )
            .await?,
        );
    }
    for event in &events {
        evaluate_scan_rule(&f.engine, &HTTP_SCAN, event).await?;
    }
    assert!(f.assessments().await?.is_empty(), "7 distinct paths < 8");
    f.finish().await
}

/// A 5xx answer is the server's failure: a burst of them is a server-fault
/// observation under its own rule and never counts as client abuse or scanning.
#[tokio::test]
#[ignore = "requires provisioned roles in an isolated PostgreSQL test container"]
async fn server_error_burst_is_an_observation_not_client_abuse() -> Result<()> {
    let mut f = Fixture::new().await?;
    let base = t(17, 0, 0);
    let mut events = Vec::new();
    for i in 0..12 {
        events.push(f.http(base + Duration::seconds(i), "/api", 503).await?);
    }
    for event in &events {
        for rule in RULES {
            if rule.event_type == event.event_type {
                evaluate_rule(&f.engine, rule, event).await?;
            }
        }
        evaluate_scan_rule(&f.engine, &HTTP_SCAN, event).await?;
    }
    let rules: Vec<String> = f.assessments().await?.into_iter().map(|a| a.0).collect();
    assert!(
        rules.iter().all(|rule| rule == "http_server_fault_burst"),
        "{rules:?}"
    );
    assert!(!rules.is_empty());

    // The identical shape with a client error status is abuse and stays so.
    let mut g = Fixture::new().await?;
    let mut abusive = Vec::new();
    for i in 0..12 {
        abusive.push(g.http(base + Duration::seconds(i), "/api", 404).await?);
    }
    for event in &abusive {
        for rule in RULES {
            if rule.event_type == event.event_type {
                evaluate_rule(&g.engine, rule, event).await?;
            }
        }
    }
    let rules: Vec<String> = g.assessments().await?.into_iter().map(|a| a.0).collect();
    assert!(
        rules.iter().all(|rule| rule == "http_anomaly_burst"),
        "{rules:?}"
    );
    assert!(!rules.is_empty());

    // A mix below both thresholds is quiet: 6 x 404 and 6 x 503.
    let mut h = Fixture::new().await?;
    let mut mixed = Vec::new();
    for i in 0..12 {
        mixed.push(
            h.http(
                base + Duration::seconds(i),
                "/api",
                if i % 2 == 0 { 404 } else { 503 },
            )
            .await?,
        );
    }
    for event in &mixed {
        for rule in RULES {
            if rule.event_type == event.event_type {
                evaluate_rule(&h.engine, rule, event).await?;
            }
        }
    }
    assert!(h.assessments().await?.is_empty());
    h.finish().await?;
    f.finish().await
}

/// Events arrive in a different order than they occurred, each followed at once
/// by an evaluation (not all published first). The stored result must equal the
/// in-order run exactly: assessments depend on the event set, never the arrival order.
#[tokio::test]
#[ignore = "requires provisioned roles in an isolated PostgreSQL test container"]
async fn interleaved_out_of_order_arrival_equals_in_order_arrival() -> Result<()> {
    let boundary = t(18, 40, 0);
    let seconds = [-4_i64, -3, -2, -1, 0, 1, 2, 3];
    let mut in_order = Fixture::new().await?;
    for second in seconds {
        let event = in_order.ssh(boundary + Duration::seconds(second)).await?;
        in_order.run_ssh(&event).await?;
    }
    let mut shuffled = Fixture::new().await?;
    for index in [7_usize, 0, 6, 1, 5, 2, 4, 3] {
        let event = shuffled
            .ssh(boundary + Duration::seconds(seconds[index]))
            .await?;
        shuffled.run_ssh(&event).await?;
    }
    let expected = in_order.assessments().await?;
    assert_eq!(expected.len(), 1, "{expected:?}");
    assert_eq!(shuffled.assessments().await?, expected);
    assert_eq!(shuffled.candidates().await?, 1);
    // A very late event (100 s before the boundary) joins both windows it belongs
    // to: the shifted window grows to 9, and the primary window before the boundary
    // now holds 5 events (4 + this one) and fires on its own.
    let late = shuffled.ssh(boundary + Duration::seconds(-100)).await?;
    shuffled.run_ssh(&late).await?;
    shuffled.run_ssh(&late).await?; // redelivery of the same event changes nothing
    let after = shuffled.assessments().await?;
    assert_eq!(
        after,
        vec![
            (
                "ssh_bruteforce".to_string(),
                boundary - Duration::seconds(300),
                5
            ),
            (
                "ssh_bruteforce".to_string(),
                boundary - Duration::seconds(150),
                9
            ),
        ]
    );
    assert_eq!(
        shuffled.candidates().await?,
        1,
        "still one incident candidate"
    );
    in_order.finish().await?;
    shuffled.finish().await
}

/// Roughly one failed login every two minutes never reaches five in five minutes, but is
/// thirty an hour: the hourly rule sees it, the five-minute rule must stay silent.
#[tokio::test]
#[ignore = "requires provisioned roles in an isolated PostgreSQL test container"]
async fn a_slow_ssh_attacker_is_seen_by_the_hourly_rule_only() -> Result<()> {
    let mut f = Fixture::new().await?;
    let start = t(15, 0, 30);
    let mut events = Vec::new();
    for i in 0..30 {
        events.push(f.ssh(start + Duration::seconds(120 * i)).await?);
    }
    for event in &events {
        evaluate_rule(&f.engine, &SSH_BRUTEFORCE, event).await?;
        evaluate_rule(&f.engine, &SSH_BRUTEFORCE_SLOW, event).await?;
    }
    let found = f.assessments().await?;
    assert!(
        found
            .iter()
            .all(|(rule, _, _)| rule == "ssh_bruteforce_slow"),
        "the five-minute rule must not fire: {found:?}"
    );
    // primary window 15:00-16:00 holds all 30; the shifted windows 14:30-15:30 and 15:30-16:30
    // each hold half of them (15), which is exactly the threshold
    let mut counts: Vec<i32> = found.iter().map(|(_, _, c)| *c).collect();
    counts.sort();
    assert_eq!(counts, vec![15, 15, 30], "{found:?}");
    f.finish().await?;
    Ok(())
}

/// Twelve an hour (one every five minutes) is below the hourly threshold in every window of
/// either grid: nothing fires, the honest limit of this rule.
#[tokio::test]
#[ignore = "requires provisioned roles in an isolated PostgreSQL test container"]
async fn a_failure_every_five_minutes_stays_quiet_in_both_rules() -> Result<()> {
    let mut f = Fixture::new().await?;
    let start = t(16, 0, 10);
    let mut events = Vec::new();
    for i in 0..24 {
        events.push(f.ssh(start + Duration::seconds(300 * i)).await?);
    }
    for event in &events {
        evaluate_rule(&f.engine, &SSH_BRUTEFORCE, event).await?;
        evaluate_rule(&f.engine, &SSH_BRUTEFORCE_SLOW, event).await?;
    }
    assert!(f.assessments().await?.is_empty());
    f.finish().await?;
    Ok(())
}

/// A very busy source must not make the long window expensive: a firing reads and records at
/// most `max_members` events (severity already saturates there).
#[tokio::test]
#[ignore = "requires provisioned roles in an isolated PostgreSQL test container"]
async fn the_hourly_rule_reads_a_bounded_number_of_events_for_a_busy_source() -> Result<()> {
    let mut f = Fixture::new().await?;
    let start = t(17, 0, 5);
    let mut last = None;
    for i in 0..200 {
        last = Some(f.ssh(start + Duration::seconds(15 * i)).await?);
    }
    evaluate_rule(&f.engine, &SSH_BRUTEFORCE_SLOW, &last.unwrap()).await?;
    let found: Vec<(i32, String)> = sqlx::query_as(
        "SELECT event_count, severity FROM security_assessments WHERE resource=$1 AND rule_id='ssh_bruteforce_slow'",
    )
    .bind(&f.resource)
    .fetch_all(f.owner.pool())
    .await?;
    assert!(!found.is_empty());
    assert!(
        found
            .iter()
            .all(|(count, severity)| *count == 61 && severity == "critical"),
        "{found:?}"
    );
    let evidence: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM security_assessment_events e JOIN security_assessments a ON a.id=e.assessment_id WHERE a.resource=$1 AND a.rule_id='ssh_bruteforce_slow'",
    )
    .bind(&f.resource)
    .fetch_one(f.owner.pool())
    .await?;
    assert_eq!(evidence, 61 * found.len() as i64);
    f.finish().await?;
    Ok(())
}

/// One activity, one finding: a burst the five-minute rule already flagged is not reported a
/// second time by the hourly rule, even though it also has >= 15 failures in the hour.
#[tokio::test]
#[ignore = "requires provisioned roles in an isolated PostgreSQL test container"]
async fn the_hourly_rule_yields_to_the_five_minute_finding_of_the_same_activity() -> Result<()> {
    let mut f = Fixture::new().await?;
    let start = t(18, 0, 5);
    let mut events = Vec::new();
    for i in 0..30 {
        events.push(f.ssh(start + Duration::seconds(2 * i)).await?);
    }
    for event in &events {
        evaluate_rule(&f.engine, &SSH_BRUTEFORCE, event).await?;
        evaluate_rule(&f.engine, &SSH_BRUTEFORCE_SLOW, event).await?;
    }
    let found = f.assessments().await?;
    assert!(!found.is_empty());
    assert!(
        found.iter().all(|(rule, _, _)| rule == "ssh_bruteforce"),
        "{found:?}"
    );
    f.finish().await?;
    Ok(())
}
