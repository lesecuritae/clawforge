use clawforge_storage::{database_url_from_env, PostgresStore};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let database_url = database_url_from_env()?;
    let store = PostgresStore::connect(&database_url).await?;
    let status = store.readiness().await?;
    if !status.current {
        anyhow::bail!("database migrations did not reach the expected schema version");
    }
    println!(
        "database migrations are current at version {}",
        status.latest
    );
    Ok(())
}
