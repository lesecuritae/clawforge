//! Fixture sender for the Security Event Layer batch ingress endpoint
//! (roadmap `security-events-ingress`). Sends every fixture in
//! `clawforge_security_events::fixtures` as one batch, for manually
//! verifying a running ingress endpoint - or a real sensor integration
//! being built against it - by hand, without writing throwaway curl
//! commands to reconstruct the eleven event shapes.
//!
//! Usage:
//!   CLAWFORGE_SECURITY_EVENTS_URL=http://127.0.0.1:8080 \
//!   CLAWFORGE_SECURITY_EVENTS_SENSOR_CREDENTIAL=<a registered sensor's raw credential> \
//!   cargo run -p clawforge-api --bin send-security-event-fixtures
//!
//! The credential must belong to a sensor already registered via
//! `PostgresStore::register_security_sensor` - this sender does not
//! register one itself, since who is allowed to do that is a decision for
//! whatever eventually manages the sensor registry (out of scope here, see
//! docs/security-events.md).

use clawforge_security_events::fixtures;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let base_url = std::env::var("CLAWFORGE_SECURITY_EVENTS_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:8080".to_string());
    let credential = std::env::var("CLAWFORGE_SECURITY_EVENTS_SENSOR_CREDENTIAL").map_err(|_| {
        anyhow::anyhow!(
            "set CLAWFORGE_SECURITY_EVENTS_SENSOR_CREDENTIAL to a registered sensor's raw credential"
        )
    })?;

    let mut items = fixtures::all();
    // Fixtures carry a fixed, long-past timestamp so their own JSON stays
    // stable for tests; a live ingress endpoint's clock-skew check would
    // reject that outright, so bring each one to "now" first - the same
    // way a real sensor reports its own current clock, not a canned one.
    let now = chrono::Utc::now();
    for item in &mut items {
        item.occurred_at = now;
    }

    let client = reqwest::Client::new();
    let response = client
        .post(format!("{base_url}/internal/security-events/batch"))
        .bearer_auth(&credential)
        .json(&items)
        .send()
        .await?;
    let status = response.status();
    let body: serde_json::Value = response.json().await?;
    println!("{status}");
    println!("{}", serde_json::to_string_pretty(&body)?);
    if !status.is_success() {
        anyhow::bail!("fixture batch was rejected");
    }
    Ok(())
}
