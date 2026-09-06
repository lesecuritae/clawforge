use clawforge_storage::PostgresStore;

#[tokio::test]
#[ignore = "requires an isolated PostgreSQL test container"]
async fn migrations_and_restart_persist() -> anyhow::Result<()> {
    let url = std::env::var("CLAWFORGE_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))?;
    let store = PostgresStore::connect(&url).await?;
    store.healthcheck().await?;
    assert!(store.migration_version().await?.is_some());
    drop(store);
    let restarted = PostgresStore::connect(&url).await?;
    restarted.healthcheck().await?;
    Ok(())
}
