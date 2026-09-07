use std::{
    env,
    sync::Arc,
    time::{Duration, Instant},
};

use chrono::{Duration as ChronoDuration, Utc};
use clawforge_intelligence::{
    network_providers, phase_one_providers, AsnRecord, BgpEvent, Indicator, IndicatorSink,
    IndicatorType, IntelligenceEvent, NetworkBatch, NetworkObservation, NetworkProvider,
    NetworkSink, ProviderAdapter, RpkiRecord,
};
use clawforge_risk::{RiskEngine, RiskSignals};
use clawforge_storage::PostgresStore;
use tracing::{error, info, warn};
use uuid::Uuid;

struct ScheduledProvider {
    adapter: Arc<dyn ProviderAdapter>,
    interval: Duration,
    next_run: Instant,
    failures: u32,
}

struct ScheduledNetworkProvider {
    adapter: Arc<dyn NetworkProvider>,
    interval: Duration,
    next_run: Instant,
    failures: u32,
}

#[derive(Default)]
pub struct RiskConsumer {
    engine: RiskEngine,
}

#[derive(Clone)]
struct RedisRunLock {
    client: redis::Client,
    key: String,
    token: String,
}

impl RedisRunLock {
    fn from_env() -> anyhow::Result<Option<Self>> {
        let Ok(url) = env::var("REDIS_URL") else {
            return Ok(None);
        };
        if url.trim().is_empty() {
            return Ok(None);
        }
        Ok(Some(Self {
            client: redis::Client::open(url)?,
            key: env::var("CLAWFORGE_SCHEDULER_LOCK_KEY")
                .unwrap_or_else(|_| "clawforge:scheduler:lock".to_string()),
            token: Uuid::new_v4().to_string(),
        }))
    }

    async fn acquire(&self) -> redis::RedisResult<bool> {
        let mut connection = self.client.get_multiplexed_async_connection().await?;
        let result: Option<String> = redis::cmd("SET")
            .arg(&self.key)
            .arg(&self.token)
            .arg("NX")
            .arg("EX")
            .arg(120)
            .query_async(&mut connection)
            .await?;
        Ok(result.is_some())
    }

    async fn release(&self) -> redis::RedisResult<()> {
        let mut connection = self.client.get_multiplexed_async_connection().await?;
        let _: i64 = redis::cmd("EVAL")
            .arg("if redis.call('get', KEYS[1]) == ARGV[1] then return redis.call('del', KEYS[1]) else return 0 end")
            .arg(1)
            .arg(&self.key)
            .arg(&self.token)
            .query_async(&mut connection)
            .await?;
        Ok(())
    }
}

impl RiskConsumer {
    pub async fn consume(
        &self,
        indicators: &[Indicator],
        store: &PostgresStore,
    ) -> anyhow::Result<()> {
        for indicator in indicators {
            let assessment = self.engine.evaluate(
                &NetworkObservation::default(),
                std::slice::from_ref(indicator),
                &RiskSignals::default(),
            );
            let id = store.upsert_indicator(indicator).await?;
            let reason = if assessment.reasons.is_empty() {
                "provider indicator".to_string()
            } else {
                assessment.reasons.join("; ")
            };
            store
                .record_risk_event(
                    id,
                    indicator,
                    assessment.negative_score as i16,
                    assessment.risk_score,
                    assessment.trust_score,
                    &reason,
                )
                .await?;
            record_event(
                store,
                "new_threat_indicator",
                &indicator.source,
                &indicator.value,
                if assessment.risk_score >= 70 { "high" } else { "info" },
                &reason,
                serde_json::json!({"risk_score": assessment.risk_score, "trust_score": assessment.trust_score}),
            )
            .await;
        }
        Ok(())
    }

    pub async fn consume_network(
        &self,
        batch: &NetworkBatch,
        store: &PostgresStore,
    ) -> anyhow::Result<usize> {
        store.upsert_asn_records(&batch.asn_records).await?;
        store.upsert_bgp_events(&batch.bgp_events).await?;
        store.upsert_rpki_records(&batch.rpki_records).await?;

        let mut count = 0;
        for record in &batch.asn_records {
            let indicator = asn_indicator(record);
            let assessment = self.engine.evaluate(
                &NetworkObservation {
                    asn: Some(record.asn.clone()),
                    ..NetworkObservation::default()
                },
                std::slice::from_ref(&indicator),
                &RiskSignals::from_asn(record),
            );
            let id = store.upsert_indicator(&indicator).await?;
            store
                .record_risk_event(
                    id,
                    &indicator,
                    assessment.negative_score as i16,
                    assessment.risk_score,
                    assessment.trust_score,
                    &assessment.reasons.join("; "),
                )
                .await?;
            record_event(
                store,
                "asn_change",
                &record.provider,
                &record.asn,
                "info",
                &assessment.reasons.join("; "),
                serde_json::json!({"country": record.country, "network_type": record.network_type}),
            )
            .await;
            count += 1;
        }
        for event in &batch.bgp_events {
            let indicator = bgp_indicator(event);
            let assessment = self.engine.evaluate(
                &NetworkObservation {
                    prefix: Some(event.prefix.clone()),
                    bgp_status: event.status.clone(),
                    rpki_status: event.rpki_status.clone(),
                    ..NetworkObservation::default()
                },
                std::slice::from_ref(&indicator),
                &RiskSignals::from_bgp(event),
            );
            let id = store.upsert_indicator(&indicator).await?;
            store
                .record_risk_event(
                    id,
                    &indicator,
                    assessment.negative_score as i16,
                    assessment.risk_score,
                    assessment.trust_score,
                    &assessment.reasons.join("; "),
                )
                .await?;
            record_event(
                store,
                "bgp_change",
                &event.source,
                &event.prefix,
                if matches!(event.status, clawforge_intelligence::BgpStatus::Anomalous) { "high" } else { "medium" },
                &assessment.reasons.join("; "),
                serde_json::json!({"previous_asn": event.previous_asn, "new_asn": event.new_asn, "status": format!("{:?}", event.status)}),
            )
            .await;
            count += 1;
        }
        for record in &batch.rpki_records {
            let indicator = rpki_indicator(record);
            let assessment = self.engine.evaluate(
                &NetworkObservation {
                    prefix: Some(record.prefix.clone()),
                    asn: Some(record.asn.clone()),
                    rpki_status: record.status.clone(),
                    ..NetworkObservation::default()
                },
                std::slice::from_ref(&indicator),
                &RiskSignals::from_rpki(record),
            );
            let id = store.upsert_indicator(&indicator).await?;
            store
                .record_risk_event(
                    id,
                    &indicator,
                    assessment.negative_score as i16,
                    assessment.risk_score,
                    assessment.trust_score,
                    &assessment.reasons.join("; "),
                )
                .await?;
            if matches!(record.status, clawforge_intelligence::RpkiStatus::Invalid) {
                record_event(
                    store,
                    "rpki_invalid",
                    &record.source,
                    &record.prefix,
                    "high",
                    "RPKI validation returned Invalid",
                    serde_json::json!({"asn": record.asn}),
                )
                .await;
            }
            count += 1;
        }
        Ok(count)
    }
}

async fn record_event(
    store: &PostgresStore,
    event_type: &str,
    source: &str,
    resource: &str,
    severity: &str,
    reason: &str,
    details: serde_json::Value,
) {
    if let Err(error) = store
        .record_intelligence_event(&IntelligenceEvent {
            event_type: event_type.to_string(),
            timestamp: Utc::now(),
            source: source.to_string(),
            severity: severity.to_string(),
            reason: reason.to_string(),
            resource: resource.to_string(),
            details,
        })
        .await
    {
        warn!(%error, event_type, source, "could not persist intelligence event");
    }
}

fn network_indicator(
    value: String,
    indicator_type: IndicatorType,
    source: String,
    metadata: serde_json::Value,
) -> Indicator {
    let now = Utc::now();
    Indicator {
        value,
        indicator_type,
        categories: vec!["network-intelligence".to_string()],
        confidence: 70,
        source,
        first_seen: now,
        last_seen: now,
        expires_at: now + ChronoDuration::hours(24),
        metadata,
    }
}

fn asn_indicator(record: &AsnRecord) -> Indicator {
    network_indicator(
        record.asn.clone(),
        IndicatorType::Asn,
        record.provider.clone(),
        serde_json::json!({"name": record.name, "country": record.country, "registry": record.registry, "network_type": record.network_type}),
    )
}

fn bgp_indicator(event: &BgpEvent) -> Indicator {
    network_indicator(
        event.prefix.clone(),
        IndicatorType::Prefix,
        event.source.clone(),
        serde_json::json!({"origin_asn": event.origin_asn, "previous_asn": event.previous_asn, "new_asn": event.new_asn, "status": format!("{:?}", event.status)}),
    )
}

fn rpki_indicator(record: &RpkiRecord) -> Indicator {
    network_indicator(
        record.prefix.clone(),
        IndicatorType::Prefix,
        record.source.clone(),
        serde_json::json!({"asn": record.asn, "rpki_status": format!("{:?}", record.status)}),
    )
}

pub struct Scheduler {
    jobs: Vec<ScheduledProvider>,
    network_jobs: Vec<ScheduledNetworkProvider>,
    consumer: RiskConsumer,
    busy: bool,
    redis_lock: Option<RedisRunLock>,
}

impl Scheduler {
    pub fn phase_one(enabled: bool) -> anyhow::Result<Self> {
        let network_enabled = env::var("CLAWFORGE_ENABLE_NETWORK")
            .map(|value| value.eq_ignore_ascii_case("true") || value == "1")
            .unwrap_or(false);
        if !enabled && !network_enabled {
            return Ok(Self {
                jobs: Vec::new(),
                network_jobs: Vec::new(),
                consumer: RiskConsumer::default(),
                busy: false,
                redis_lock: RedisRunLock::from_env()?,
            });
        }
        let now = Instant::now();
        let mut jobs = Vec::new();
        if enabled {
            for adapter in phase_one_providers()? {
                let interval =
                    Duration::from_secs(adapter.provider().interval_seconds.max(30) as u64);
                jobs.push(ScheduledProvider {
                    adapter: Arc::from(adapter),
                    interval,
                    next_run: now,
                    failures: 0,
                });
            }
        }
        let network_jobs = if network_enabled {
            network_providers()?
                .into_iter()
                .map(|adapter| {
                    let interval =
                        Duration::from_secs(adapter.provider().interval_seconds.max(30) as u64);
                    ScheduledNetworkProvider {
                        adapter: Arc::from(adapter),
                        interval,
                        next_run: now,
                        failures: 0,
                    }
                })
                .collect()
        } else {
            Vec::new()
        };
        Ok(Self {
            jobs,
            network_jobs,
            consumer: RiskConsumer::default(),
            busy: false,
            redis_lock: RedisRunLock::from_env()?,
        })
    }

    pub fn provider_count(&self) -> usize {
        self.jobs.len() + self.network_jobs.len()
    }

    pub async fn run_due(&mut self, store: &PostgresStore) {
        if self.busy {
            warn!("scheduler run skipped because a previous run is still active");
            return;
        }
        self.busy = true;
        let lock_held = if let Some(lock) = &self.redis_lock {
            match lock.acquire().await {
                Ok(true) => true,
                Ok(false) => {
                    self.busy = false;
                    warn!("scheduler run skipped because Redis lock is held");
                    return;
                }
                Err(error) => {
                    self.busy = false;
                    warn!(%error, "scheduler run skipped because Redis lock could not be acquired");
                    return;
                }
            }
        } else {
            false
        };
        if let Err(error) = store.expire_indicators(Utc::now()).await {
            warn!(%error, "indicator expiry cleanup failed");
        }
        self.process_manual_syncs(store).await;
        let now = Instant::now();
        for job in &mut self.jobs {
            if job.next_run > now {
                continue;
            }
            let provider = job.adapter.provider();
            if let Err(error) = store.upsert_provider(&provider).await {
                error!(provider = %provider.id, %error, "cannot persist provider metadata");
                job.next_run = Instant::now() + Duration::from_secs(60);
                continue;
            }
            if let Ok(Some(seconds)) = store.provider_interval_seconds(&provider.id).await {
                job.interval = Duration::from_secs(seconds.clamp(30, 86_400) as u64);
            }
            if !store.provider_enabled(&provider.id).await.unwrap_or(false) {
                job.next_run = Instant::now() + job.interval;
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
                    let next = Utc::now()
                        + ChronoDuration::from_std(job.interval)
                            .unwrap_or_else(|_| ChronoDuration::minutes(15));
                    let duration_ms = started.elapsed().as_millis().min(i64::MAX as u128) as i64;
                    let last_data_at = indicators_last_seen(job.adapter.as_ref(), store).await;
                    if let Err(error) = store
                        .provider_succeeded(
                            &provider.id,
                            next,
                            count as i32,
                            duration_ms,
                            last_data_at,
                        )
                        .await
                    {
                        error!(provider = %provider.id, %error, "cannot persist provider success");
                    }
                    record_event(
                        store,
                        "provider_sync",
                        &provider.source,
                        &provider.id,
                        "info",
                        "provider synchronization completed",
                        serde_json::json!({"indicators": count, "duration_ms": duration_ms}),
                    )
                    .await;
                    info!(provider = %provider.id, indicators = count, "provider synchronization completed");
                }
                Err(error) => {
                    job.failures = job.failures.saturating_add(1);
                    let exponent = job.failures.min(6);
                    let backoff = job
                        .interval
                        .checked_mul(2u32.pow(exponent))
                        .unwrap_or(Duration::from_secs(3600))
                        .min(Duration::from_secs(3600));
                    job.next_run = Instant::now() + backoff;
                    let next = Utc::now()
                        + ChronoDuration::from_std(backoff)
                            .unwrap_or_else(|_| ChronoDuration::hours(1));
                    let duration_ms = started.elapsed().as_millis().min(i64::MAX as u128) as i64;
                    if let Err(status_error) = store
                        .provider_failed(&provider.id, &error.to_string(), next, 0, duration_ms)
                        .await
                    {
                        error!(provider = %provider.id, %status_error, "cannot persist provider failure");
                    }
                    record_event(
                        store,
                        "provider_error",
                        &provider.source,
                        &provider.id,
                        "warning",
                        &error.to_string(),
                        serde_json::json!({"failures": job.failures, "duration_ms": duration_ms}),
                    )
                    .await;
                    warn!(provider = %provider.id, failures = job.failures, %error, "provider synchronization failed; backing off");
                }
            }
        }
        for job in &mut self.network_jobs {
            if job.next_run > now {
                continue;
            }
            let provider = job.adapter.provider();
            if let Err(error) = store.upsert_provider(&provider).await {
                error!(provider = %provider.id, %error, "cannot persist network provider metadata");
                job.next_run = Instant::now() + Duration::from_secs(60);
                continue;
            }
            if let Ok(Some(seconds)) = store.provider_interval_seconds(&provider.id).await {
                job.interval = Duration::from_secs(seconds.clamp(30, 86_400) as u64);
            }
            if !store.provider_enabled(&provider.id).await.unwrap_or(false) {
                job.next_run = Instant::now() + job.interval;
                continue;
            }
            if let Err(error) = store.provider_started(&provider.id).await {
                error!(provider = %provider.id, %error, "cannot persist network provider start");
            }
            let started = Instant::now();
            match Self::sync_network_provider(job.adapter.as_ref(), store, &self.consumer).await {
                Ok(count) => {
                    job.failures = 0;
                    job.next_run = Instant::now() + job.interval;
                    let next = Utc::now()
                        + ChronoDuration::from_std(job.interval)
                            .unwrap_or_else(|_| ChronoDuration::hours(1));
                    let duration_ms = started.elapsed().as_millis().min(i64::MAX as u128) as i64;
                    let last_data_at = store.latest_indicator_at(&provider.id).await.ok().flatten();
                    if let Err(error) = store
                        .provider_succeeded(
                            &provider.id,
                            next,
                            count as i32,
                            duration_ms,
                            last_data_at,
                        )
                        .await
                    {
                        error!(provider = %provider.id, %error, "cannot persist network provider success");
                    }
                    record_event(
                        store,
                        "provider_sync",
                        &provider.source,
                        &provider.id,
                        "info",
                        "network provider synchronization completed",
                        serde_json::json!({"records": count, "duration_ms": duration_ms}),
                    )
                    .await;
                    info!(provider = %provider.id, records = count, "network provider synchronization completed");
                }
                Err(error) => {
                    job.failures = job.failures.saturating_add(1);
                    let exponent = job.failures.min(6);
                    let backoff = job
                        .interval
                        .checked_mul(2u32.pow(exponent))
                        .unwrap_or(Duration::from_secs(3600))
                        .min(Duration::from_secs(3600));
                    job.next_run = Instant::now() + backoff;
                    let next = Utc::now()
                        + ChronoDuration::from_std(backoff)
                            .unwrap_or_else(|_| ChronoDuration::hours(1));
                    let duration_ms = started.elapsed().as_millis().min(i64::MAX as u128) as i64;
                    if let Err(status_error) = store
                        .provider_failed(&provider.id, &error.to_string(), next, 0, duration_ms)
                        .await
                    {
                        error!(provider = %provider.id, %status_error, "cannot persist network provider failure");
                    }
                    record_event(
                        store,
                        "provider_error",
                        &provider.source,
                        &provider.id,
                        "warning",
                        &error.to_string(),
                        serde_json::json!({"failures": job.failures, "duration_ms": duration_ms}),
                    )
                    .await;
                    warn!(provider = %provider.id, failures = job.failures, elapsed_ms = duration_ms, %error, "network provider synchronization failed; backing off");
                }
            }
        }
        if lock_held {
            if let Some(lock) = &self.redis_lock {
                if let Err(error) = lock.release().await {
                    warn!(%error, "could not release Redis scheduler lock");
                }
            }
        }
        self.busy = false;
    }

    async fn process_manual_syncs(&self, store: &PostgresStore) {
        let requests = match store.claim_provider_sync_requests(20).await {
            Ok(requests) => requests,
            Err(error) => {
                warn!(%error, "could not claim manual provider sync requests");
                return;
            }
        };
        for request in requests {
            let started = Instant::now();
            let mut result = Err(anyhow::anyhow!("provider is not enabled or unknown"));
            if !store
                .provider_enabled(&request.provider_id)
                .await
                .unwrap_or(false)
            {
                let _ = store
                    .finish_provider_sync_request(request.id, false, Some("provider is disabled"))
                    .await;
                continue;
            }
            if let Some(job) = self
                .jobs
                .iter()
                .find(|job| job.adapter.provider().id == request.provider_id)
            {
                let _ = store.provider_started(&request.provider_id).await;
                result = Self::sync_provider(job.adapter.as_ref(), store, &self.consumer).await;
            } else if let Some(job) = self
                .network_jobs
                .iter()
                .find(|job| job.adapter.provider().id == request.provider_id)
            {
                let _ = store.provider_started(&request.provider_id).await;
                result =
                    Self::sync_network_provider(job.adapter.as_ref(), store, &self.consumer).await;
            }
            match result {
                Ok(count) => {
                    let duration_ms = started.elapsed().as_millis().min(i64::MAX as u128) as i64;
                    let _ = store
                        .provider_succeeded(
                            &request.provider_id,
                            Utc::now() + ChronoDuration::minutes(15),
                            count as i32,
                            duration_ms,
                            store
                                .latest_indicator_at(&request.provider_id)
                                .await
                                .ok()
                                .flatten(),
                        )
                        .await;
                    if let Err(error) = store
                        .finish_provider_sync_request(request.id, true, None)
                        .await
                    {
                        warn!(%error, "could not persist manual sync result");
                    }
                    record_event(
                        store,
                        "provider_manual_sync",
                        &request.provider_id,
                        &request.provider_id,
                        "info",
                        "manual provider synchronization completed",
                        serde_json::json!({"records":count}),
                    )
                    .await;
                }
                Err(error) => {
                    let duration_ms = started.elapsed().as_millis().min(i64::MAX as u128) as i64;
                    let _ = store
                        .provider_failed(
                            &request.provider_id,
                            &error.to_string(),
                            Utc::now() + ChronoDuration::minutes(15),
                            0,
                            duration_ms,
                        )
                        .await;
                    if let Err(status_error) = store
                        .finish_provider_sync_request(request.id, false, Some(&error.to_string()))
                        .await
                    {
                        warn!(%status_error, "could not persist manual sync failure");
                    }
                    record_event(
                        store,
                        "provider_error",
                        &request.provider_id,
                        &request.provider_id,
                        "warning",
                        &error.to_string(),
                        serde_json::json!({"manual":true}),
                    )
                    .await;
                }
            }
        }
    }

    async fn sync_provider(
        adapter: &dyn ProviderAdapter,
        store: &PostgresStore,
        consumer: &RiskConsumer,
    ) -> anyhow::Result<usize> {
        let feed = adapter.fetch().await?;
        adapter.validate(&feed)?;
        let indicators = adapter.normalize(&feed)?;
        adapter
            .store(&indicators, store as &dyn IndicatorSink)
            .await?;
        consumer.consume(&indicators, store).await?;
        Ok(indicators.len())
    }

    async fn sync_network_provider(
        adapter: &dyn NetworkProvider,
        store: &PostgresStore,
        consumer: &RiskConsumer,
    ) -> anyhow::Result<usize> {
        let feed = adapter.fetch().await?;
        adapter.validate(&feed)?;
        let batch = adapter.normalize(&feed)?;
        consumer.consume_network(&batch, store).await
    }
}

async fn indicators_last_seen(
    adapter: &dyn ProviderAdapter,
    store: &PostgresStore,
) -> Option<chrono::DateTime<Utc>> {
    // The store owns the authoritative timestamps. The successful sync has
    // already persisted the normalized indicators, so derive the newest data
    // timestamp from that provider's rows for the status record.
    store
        .latest_indicator_at(&adapter.provider().id)
        .await
        .ok()
        .flatten()
}
