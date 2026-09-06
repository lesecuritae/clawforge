//! PostgreSQL persistence boundary.
//!
//! All SQL is kept behind this crate so the API and worker do not depend on
//! database details. SQLite can be used by future test adapters; production
//! runtime is PostgreSQL through sqlx.

use anyhow::{Context, Result};
use sqlx::{postgres::PgPoolOptions, PgPool, Row};

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("../migrations");

#[derive(Clone)]
pub struct PostgresStore {
    pool: PgPool,
}

impl PostgresStore {
    pub async fn connect(database_url: &str) -> Result<Self> {
        let pool = PgPoolOptions::new()
            .max_connections(10)
            .connect(database_url)
            .await
            .context("connect to PostgreSQL")?;
        MIGRATOR.run(&pool).await.context("run database migrations")?;
        Ok(Self { pool })
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    pub async fn healthcheck(&self) -> Result<()> {
        sqlx::query("SELECT 1").execute(&self.pool).await?;
        Ok(())
    }

    pub async fn migration_version(&self) -> Result<Option<String>> {
        let row = sqlx::query("SELECT version FROM _sqlx_migrations ORDER BY version DESC LIMIT 1")
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(|value| value.get::<i64, _>("version").to_string()))
    }

    pub async fn record_audit_event(
        &self,
        actor: &str,
        action: &str,
        resource: &str,
        details: serde_json::Value,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO audit_events (actor, action, resource, details) VALUES ($1, $2, $3, $4)",
        )
        .bind(actor)
        .bind(action)
        .bind(resource)
        .bind(details)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}
