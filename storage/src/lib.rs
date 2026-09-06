//! PostgreSQL persistence boundary.
//!
//! All SQL is kept behind this crate so the API and worker do not depend on
//! database details. SQLite can be used by future test adapters; production
//! runtime is PostgreSQL through sqlx.

use async_trait::async_trait;
use anyhow::{Context, Result};
use clawforge_intelligence::{Indicator, IndicatorSink, Provider, ProviderError};
use sqlx::{postgres::PgPoolOptions, PgPool, Row};
use std::{env, fs};

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("../migrations");

#[derive(Clone)]
pub struct PostgresStore {
    pool: PgPool,
}

impl PostgresStore {
    pub async fn connect(database_url: &str) -> Result<Self> {
        let pool = PgPoolOptions::new()
            .min_connections(1)
            .max_connections(10)
            .acquire_timeout(std::time::Duration::from_secs(10))
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

    pub async fn readiness(&self) -> Result<MigrationStatus> {
        self.healthcheck().await?;
        let row = sqlx::query("SELECT COUNT(*) AS count, COALESCE(MAX(version), 0) AS latest FROM _sqlx_migrations")
            .fetch_one(&self.pool)
            .await?;
        let applied = row.get::<i64, _>("count") as usize;
        let latest = row.get::<i64, _>("latest");
        let expected = MIGRATOR.iter().count();
        let expected_latest = MIGRATOR.iter().map(|migration| migration.version).max().unwrap_or(0);
        Ok(MigrationStatus { applied, expected, latest, expected_latest, current: applied == expected && latest == expected_latest })
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

    pub async fn upsert_provider(&self, provider: &Provider) -> Result<()> {
        sqlx::query("INSERT INTO providers (id, name, source, interval_seconds, confidence, enabled) VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (id) DO UPDATE SET name=EXCLUDED.name, source=EXCLUDED.source, interval_seconds=EXCLUDED.interval_seconds, confidence=EXCLUDED.confidence, enabled=EXCLUDED.enabled, updated_at=NOW()")
            .bind(&provider.id).bind(&provider.name).bind(&provider.source)
            .bind(provider.interval_seconds).bind(provider.confidence as i16).bind(provider.enabled)
            .execute(&self.pool).await?;
        Ok(())
    }

    pub async fn provider_started(&self, provider_id: &str) -> Result<()> {
        sqlx::query("INSERT INTO provider_status (provider_id, state, last_started_at, updated_at) VALUES ($1,'running',NOW(),NOW()) ON CONFLICT (provider_id) DO UPDATE SET state='running', last_started_at=NOW(), updated_at=NOW()")
            .bind(provider_id).execute(&self.pool).await?;
        Ok(())
    }

    pub async fn provider_succeeded(&self, provider_id: &str, next_run: chrono::DateTime<chrono::Utc>, indicator_count: i32, sync_duration_ms: i64) -> Result<()> {
        sqlx::query("INSERT INTO provider_status (provider_id, state, last_success_at, next_run_at, consecutive_failures, last_error, indicator_count, sync_duration_ms, updated_at) VALUES ($1,'ok',NOW(),$2,0,NULL,$3,$4,NOW()) ON CONFLICT (provider_id) DO UPDATE SET state='ok', last_success_at=NOW(), next_run_at=$2, consecutive_failures=0, last_error=NULL, indicator_count=$3, sync_duration_ms=$4, updated_at=NOW()")
            .bind(provider_id).bind(next_run).bind(indicator_count).bind(sync_duration_ms).execute(&self.pool).await?;
        Ok(())
    }

    pub async fn provider_failed(&self, provider_id: &str, error: &str, next_run: chrono::DateTime<chrono::Utc>, indicator_count: i32, sync_duration_ms: i64) -> Result<()> {
        sqlx::query("INSERT INTO provider_status (provider_id, state, next_run_at, consecutive_failures, last_error, indicator_count, sync_duration_ms, updated_at) VALUES ($1,'error',$2,1,$3,$4,$5,NOW()) ON CONFLICT (provider_id) DO UPDATE SET state='error', next_run_at=$2, consecutive_failures=provider_status.consecutive_failures+1, last_error=$3, indicator_count=$4, sync_duration_ms=$5, updated_at=NOW()")
            .bind(provider_id).bind(next_run).bind(error).bind(indicator_count).bind(sync_duration_ms).execute(&self.pool).await?;
        Ok(())
    }

    pub async fn expire_indicators(&self, now: chrono::DateTime<chrono::Utc>) -> Result<u64> {
        let result = sqlx::query("DELETE FROM indicators WHERE expires_at <= $1").bind(now).execute(&self.pool).await?;
        Ok(result.rows_affected())
    }

    pub async fn upsert_indicator(&self, indicator: &Indicator) -> Result<i64> {
        let row = sqlx::query("INSERT INTO indicators (value, indicator_type, categories, confidence, source, first_seen, last_seen, expires_at, metadata) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT (value, indicator_type, source) DO UPDATE SET categories=EXCLUDED.categories, confidence=EXCLUDED.confidence, last_seen=EXCLUDED.last_seen, expires_at=EXCLUDED.expires_at, metadata=EXCLUDED.metadata RETURNING id")
            .bind(&indicator.value)
            .bind(format!("{:?}", indicator.indicator_type))
            .bind(serde_json::to_value(&indicator.categories)?)
            .bind(indicator.confidence as i16)
            .bind(&indicator.source)
            .bind(indicator.first_seen)
            .bind(indicator.last_seen)
            .bind(indicator.expires_at)
            .bind(&indicator.metadata)
            .fetch_one(&self.pool).await?;
        Ok(row.get("id"))
    }

    pub async fn record_risk_event(&self, indicator_id: i64, indicator: &Indicator, score_change: i16, risk_score: u8, trust_score: u8, reason: &str) -> Result<()> {
        sqlx::query("INSERT INTO risk_history (indicator_id, indicator, source, score_change, reason, risk_score, trust_score) VALUES ($1,$2,$3,$4,$5,$6,$7)")
            .bind(indicator_id).bind(&indicator.value).bind(&indicator.source).bind(score_change)
            .bind(reason).bind(risk_score as i16).bind(trust_score as i16)
            .execute(&self.pool).await?;
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct MigrationStatus {
    pub applied: usize,
    pub expected: usize,
    pub latest: i64,
    pub expected_latest: i64,
    pub current: bool,
}

pub fn database_url_from_env() -> Result<String> {
    if let Ok(url) = env::var("DATABASE_URL") {
        if !url.trim().is_empty() { return Ok(url); }
    }
    let path = env::var("DATABASE_URL_FILE").context("DATABASE_URL or DATABASE_URL_FILE must be configured")?;
    let url = fs::read_to_string(path).context("read DATABASE_URL_FILE")?;
    if url.trim().is_empty() { anyhow::bail!("DATABASE_URL_FILE is empty"); }
    Ok(url.trim().to_string())
}

#[async_trait]
impl IndicatorSink for PostgresStore {
    async fn upsert_indicators(&self, indicators: &[Indicator]) -> Result<usize, ProviderError> {
        let mut count = 0;
        for indicator in indicators {
            self.upsert_indicator(indicator).await.map_err(|error| ProviderError::Validation(format!("indicator storage failed: {error}")))?;
            count += 1;
        }
        Ok(count)
    }
}
