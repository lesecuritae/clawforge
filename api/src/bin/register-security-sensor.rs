//! One-time sensor registration CLI. `security-events-storage` provides
//! the `security_sensors` registry; nothing else issues credentials for it
//! yet (no admin HTTP endpoint exists for this - a deliberate, separate
//! decision, see docs/security-events.md). Generates a new high-entropy
//! credential, stores only its SHA-256 digest and a short, non-secret
//! prefix (the same shape `agent_tokens`/`api_tokens` already use), and
//! prints the raw credential once - it is never recoverable afterwards,
//! matching how the admin bootstrap token is already handled.
//!
//! Usage:
//!   DATABASE_URL_FILE=./secrets/database_api_url \
//!   cargo run -p clawforge-api --bin register-security-sensor -- <sensor-name>

use clawforge_storage::{database_url_from_env, PostgresStore};
use sha2::{Digest, Sha256};
use uuid::Uuid;

fn digest(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn new_secret() -> String {
    Uuid::new_v4().to_string() + &Uuid::new_v4().to_string()
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let name = std::env::args()
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("usage: register-security-sensor <sensor-name>"))?;
    let database_url = database_url_from_env()?;
    let store = PostgresStore::connect_runtime(&database_url).await?;

    let credential = new_secret();
    let prefix = &credential[..8];
    let sensor_id = store
        .register_security_sensor(
            &name,
            &digest(&credential),
            prefix,
            None,
            "register-security-sensor-cli",
        )
        .await?;

    println!("sensor registered: {sensor_id} ({name})");
    println!();
    println!("credential (shown once, store it now - it cannot be recovered):");
    println!("{credential}");
    Ok(())
}
