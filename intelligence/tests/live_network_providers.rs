//! Live replay of the network providers against their real public endpoints.
//! Ignored by default (needs egress); run on demand:
//!   cargo test -p clawforge-intelligence --test live_network_providers -- --ignored --nocapture
use clawforge_intelligence::{NetworkProvider, RpkiProvider, RpkiStatus, TeamCymruProvider};

#[tokio::test]
#[ignore]
async fn rpki_validator_answers_for_the_default_origin_prefix_pair() {
    let provider = RpkiProvider::new().unwrap();
    let feed = provider.fetch().await.unwrap();
    provider.validate(&feed).unwrap();
    let batch = provider.normalize(&feed).unwrap();
    println!("rpki: {:?}", batch.rpki_records);
    assert_eq!(batch.rpki_records.len(), 1);
    assert_eq!(batch.rpki_records[0].status, RpkiStatus::Valid);
}

#[tokio::test]
#[ignore]
async fn team_cymru_whois_answers_for_a_public_address() {
    let provider = TeamCymruProvider::new().unwrap();
    let feed = provider.fetch().await.unwrap();
    provider.validate(&feed).unwrap();
    let batch = provider.normalize(&feed).unwrap();
    println!("cymru: {:?}", batch.asn_records);
    assert_eq!(batch.asn_records.len(), 1);
    assert!(batch.asn_records[0].asn.starts_with("AS"));
}
