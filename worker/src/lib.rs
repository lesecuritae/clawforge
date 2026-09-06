use std::{sync::Arc, time::{Duration, Instant}};

use clawforge_intelligence::{phase_one_providers, Indicator, ProviderAdapter, IndicatorSink, NetworkObservation};
use clawforge_risk::{RiskEngine, RiskSignals};
use clawforge_storage::PostgresStore;
use chrono::{Duration as ChronoDuration, Utc};
use tracing::{error, info, warn};

struct ScheduledProvider {
    adapter: Arc<dyn ProviderAdapter>,
    interval: Duration,
    next_run: Instant,
    failures: u32,
}

pub struct RiskConsumer {
    engine: RiskEngine,
}

impl Default for RiskConsumer {
    fn default() -> Self { Self { engine: RiskEngine::default() } }
}

impl RiskConsumer {
    pub async fn consume(&self, indicators: &[Indicator], store: &PostgresStore) -> anyhow::Result<()> {
        for indicator in indicators {
            let assessment = self.engine.evaluate(&NetworkObservation::default(), std::slice::from_ref(indicator), &RiskSignals::default());
            let id = store.upsert_indicator(indicator).await?;
            let reason = if assessment.reasons.is_empty() { "provider indicator".to_string() } else { assessment.reasons.join("; ") };
            store.record_risk_event(id, indicator, assessment.negative_score as i16, assessment.risk_score, assessment.trust_score, &reason).await?;
        }
        Ok(())
    }
}

pub struct Scheduler {
    jobs: Vec<ScheduledProvider>,
    consumer: RiskConsumer,
}

impl Scheduler {
    pub fn phase_one(enabled: bool) -> anyhow::Result<Self> {
        if !enabled {
            return Ok(Self { jobs: Vec::new(), consumer: RiskConsumer::default() });
        }
        let now = Instant::now();
        let mut jobs = Vec::new();
        for adapter in phase_one_providers()? {
            let interval = Duration::from_secs(adapter.provider().interval_seconds.max(30) as u64);
            jobs.push(ScheduledProvider { adapter: Arc::from(adapter), interval, next_run: now, failures: 0 });
        }
        Ok(Self { jobs, consumer: RiskConsumer::default() })
    }

    pub fn provider_count(&self) -> usize { self.jobs.len() }

    pub async fn run_due(&mut self, store: &PostgresStore) {
        if let Err(error) = store.expire_indicators(Utc::now()).await {
            warn!(%error, "indicator expiry cleanup failed");
        }
        let now = Instant::now();
        for job in &mut self.jobs {
            if job.next_run > now { continue; }
            let provider = job.adapter.provider();
            if let Err(error) = store.upsert_provider(&provider).await {
                error!(provider = %provider.id, %error, "cannot persist provider metadata");
                job.next_run = Instant::now() + Duration::from_secs(60);
                continue;
            }
            if let Err(error) = store.provider_started(&provider.id).await {
                error!(provider = %provider.id, %error, "cannot persist provider start");
            }
            let started = Instant::now();
            match Self::sync_provider(job.adapter.as_ref(), store, &self.consumer).await {
                Ok(count) => {
                    job.failures = 0;
                    job.next_run = Instant::now() + job.interval;
                    let next = Utc::now() + ChronoDuration::from_std(job.interval).unwrap_or_else(|_| ChronoDuration::minutes(15));
                    let duration_ms = started.elapsed().as_millis().min(i64::MAX as u128) as i64;
                    if let Err(error) = store.provider_succeeded(&provider.id, next, count as i32, duration_ms).await { error!(provider = %provider.id, %error, "cannot persist provider success"); }
                    info!(provider = %provider.id, indicators = count, "provider synchronization completed");
                }
                Err(error) => {
                    job.failures = job.failures.saturating_add(1);
                    let exponent = job.failures.min(6);
                    let backoff = job.interval.checked_mul(2u32.pow(exponent)).unwrap_or(Duration::from_secs(3600)).min(Duration::from_secs(3600));
                    job.next_run = Instant::now() + backoff;
                    let next = Utc::now() + ChronoDuration::from_std(backoff).unwrap_or_else(|_| ChronoDuration::hours(1));
                    let duration_ms = started.elapsed().as_millis().min(i64::MAX as u128) as i64;
                    if let Err(status_error) = store.provider_failed(&provider.id, &error.to_string(), next, 0, duration_ms).await { error!(provider = %provider.id, %status_error, "cannot persist provider failure"); }
                    warn!(provider = %provider.id, failures = job.failures, %error, "provider synchronization failed; backing off");
                }
            }
        }
    }

    async fn sync_provider(adapter: &dyn ProviderAdapter, store: &PostgresStore, consumer: &RiskConsumer) -> anyhow::Result<usize> {
        let feed = adapter.fetch().await?;
        adapter.validate(&feed)?;
        let indicators = adapter.normalize(&feed)?;
        adapter.store(&indicators, store as &dyn IndicatorSink).await?;
        consumer.consume(&indicators, store).await?;
        Ok(indicators.len())
    }
}
