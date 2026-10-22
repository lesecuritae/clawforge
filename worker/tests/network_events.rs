//! Network context sync: inventory is stored, only changes and anomalies become canonical events.
//! A prefix list returns the current origin of every prefix with no previous origin; each row used
//! to be published as a medium `bgp_change` and then correlated with its own next sync, which made
//! ~194k "incidents" on production.
use anyhow::Result;
use chrono::Utc;
use clawforge_intelligence::{AsnRecord, BgpEvent, BgpStatus, NetworkBatch, RpkiStatus};
use clawforge_storage::PostgresStore;
use clawforge_worker::RiskConsumer;
use sqlx::PgPool;
use uuid::Uuid;

fn bgp(prefix: &str, status: BgpStatus, previous: Option<&str>) -> BgpEvent {
    let now = Utc::now();
    BgpEvent {
        prefix: prefix.to_string(),
        origin_asn: "AS64500".to_string(),
        previous_asn: previous.map(str::to_string),
        new_asn: Some("AS64500".to_string()),
        timestamp: now,
        source: "routeviews-test".to_string(),
        status,
        rpki_status: RpkiStatus::Unknown,
        first_seen: now,
        last_seen: now,
        change: None,
    }
}

fn asn(number: &str, name: &str) -> AsnRecord {
    let now = Utc::now();
    AsnRecord {
        asn: number.to_string(),
        name: name.to_string(),
        organisation: name.to_string(),
        provider: "peeringdb-test".to_string(),
        country: "NL".to_string(),
        registry: "ripe".to_string(),
        prefixes: vec!["192.0.2.0/24".to_string()],
        network_type: "unknown".to_string(),
        reputation: 0,
        first_seen: now,
        last_seen: now,
    }
}

async fn events_for(pool: &PgPool, resource: &str, kind: &str) -> Result<i64> {
    Ok(
        sqlx::query_scalar("SELECT count(*) FROM audit_events WHERE resource=$1 AND event_type=$2")
            .bind(resource)
            .bind(kind)
            .fetch_one(pool)
            .await?,
    )
}

#[tokio::test]
#[ignore = "requires provisioned roles in an isolated PostgreSQL test container"]
async fn only_changes_and_anomalies_become_events_inventory_does_not() -> Result<()> {
    let owner = PgPool::connect(&std::env::var("CLAWFORGE_TEST_DATABASE_URL")?).await?;
    let store =
        PostgresStore::connect_runtime(&std::env::var("CLAWFORGE_TEST_WORKER_DATABASE_URL")?)
            .await?;
    let tag = Uuid::new_v4().simple().to_string();
    let (inventory, changed, anomalous) = (
        format!("198.51.{}.0/24", u8::from_str_radix(&tag[..2], 16)?),
        format!("203.0.{}.0/24", u8::from_str_radix(&tag[2..4], 16)?),
        format!("192.0.{}.0/24", u8::from_str_radix(&tag[4..6], 16)?),
    );
    let consumer = RiskConsumer::default();
    let batch = NetworkBatch {
        bgp_events: vec![
            bgp(&inventory, BgpStatus::Unknown, None),
            bgp(&changed, BgpStatus::Changed, Some("AS64501")),
            bgp(&anomalous, BgpStatus::Anomalous, Some("AS64501")),
        ],
        ..NetworkBatch::default()
    };
    // two syncs of the same list
    consumer.consume_network(&batch, &store).await?;
    consumer.consume_network(&batch, &store).await?;
    assert_eq!(
        events_for(&owner, &inventory, "bgp_change").await?,
        0,
        "inventory is not an event"
    );
    assert_eq!(
        events_for(&owner, &changed, "bgp_change").await?,
        2,
        "a change is an event"
    );
    assert_eq!(events_for(&owner, &anomalous, "bgp_change").await?, 2);
    // inventory is still stored
    let stored: i64 = sqlx::query_scalar("SELECT count(*) FROM bgp_events WHERE prefix=$1")
        .bind(&inventory)
        .fetch_one(&owner)
        .await?;
    assert_eq!(stored, 1);
    let severity: String = sqlx::query_scalar(
        "SELECT severity FROM audit_events WHERE resource=$1 AND event_type='bgp_change' LIMIT 1",
    )
    .bind(&anomalous)
    .fetch_one(&owner)
    .await?;
    assert_eq!(severity, "high");
    Ok(())
}

#[tokio::test]
#[ignore = "requires provisioned roles in an isolated PostgreSQL test container"]
async fn an_asn_record_is_an_event_when_new_or_changed_not_when_seen_again() -> Result<()> {
    let owner = PgPool::connect(&std::env::var("CLAWFORGE_TEST_DATABASE_URL")?).await?;
    let store =
        PostgresStore::connect_runtime(&std::env::var("CLAWFORGE_TEST_WORKER_DATABASE_URL")?)
            .await?;
    let number = format!(
        "AS{}",
        4_200_000_000_u64 + (Uuid::new_v4().as_u128() % 90_000_000) as u64
    );
    let consumer = RiskConsumer::default();
    let batch = |name: &str| NetworkBatch {
        asn_records: vec![asn(&number, name)],
        ..NetworkBatch::default()
    };
    consumer
        .consume_network(&batch("Example Net"), &store)
        .await?;
    assert_eq!(
        events_for(&owner, &number, "asn_change").await?,
        1,
        "first sight"
    );
    consumer
        .consume_network(&batch("Example Net"), &store)
        .await?;
    consumer
        .consume_network(&batch("Example Net"), &store)
        .await?;
    assert_eq!(
        events_for(&owner, &number, "asn_change").await?,
        1,
        "unchanged records are inventory"
    );
    consumer
        .consume_network(&batch("Example Net Renamed"), &store)
        .await?;
    assert_eq!(
        events_for(&owner, &number, "asn_change").await?,
        2,
        "a change is an event"
    );
    Ok(())
}
