//! Routing-context enrichment for suspicious sources (off by default).
//!
//! Sends the address of a source that already produced a confident assessment to a
//! public routing API (RIPEstat) to learn its announced prefix, origin ASN(s) and
//! RPKI validity. That is the only reason an address leaves the host, so it is a
//! separate, explicit switch (`CLAWFORGE_ENABLE_IP_CONTEXT`) and bounded hard:
//!
//! * only sources the database lists as targets (recent confident assessment, live
//!   resolution, no fresh context), at most `batch` per cycle, never more than 50;
//! * never a non-public address - those are recorded as skipped without a request;
//! * requests are spaced (default 2 s, never below 1 s), one at a time;
//! * HTTP 429 pauses the whole loop for the server's `Retry-After` (bounded), and the
//!   affected source is not asked again before then; other failures back off
//!   exponentially per source in the database;
//! * a failure never overwrites good stored context and never creates evidence;
//! * results pass the database's own checks (the prefix must contain the address).
//!
//! The loop only fills a table. Whether routing facts matter to a decision is the
//! policy engine's business, and by design they are shown, not counted.
use std::time::{Duration, Instant};

use clawforge_intelligence::ip_context::{
    is_queryable, IpContextError, IpNetworkContext, RipeStatIpContext,
};
use clawforge_storage::{NetworkContextOutcome, PostgresStore};
use tracing::{info, warn};

pub const ENABLE: &str = "CLAWFORGE_ENABLE_IP_CONTEXT";
pub const MIN_CONFIDENCE: &str = "CLAWFORGE_IP_CONTEXT_MIN_CONFIDENCE";
pub const ASSESSMENT_MAX_AGE_SECONDS: &str = "CLAWFORGE_IP_CONTEXT_ASSESSMENT_MAX_AGE_SECONDS";
pub const BATCH: &str = "CLAWFORGE_IP_CONTEXT_BATCH";
pub const TTL_SECONDS: &str = "CLAWFORGE_IP_CONTEXT_TTL_SECONDS";
pub const SPACING_MILLIS: &str = "CLAWFORGE_IP_CONTEXT_SPACING_MILLIS";
pub const CYCLE_SECONDS: &str = "CLAWFORGE_IP_CONTEXT_CYCLE_SECONDS";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpContextConfig {
    pub min_confidence: i32,
    pub assessment_max_age_seconds: i32,
    pub batch: i32,
    pub ttl_seconds: i32,
    pub spacing: Duration,
    pub cycle: Duration,
}

impl IpContextConfig {
    /// `Ok(None)` unless explicitly enabled. When enabled, which sources are worth a
    /// third-party request (confidence, recency) must be configured; the politeness
    /// settings have conservative bounded defaults and cannot be set below them.
    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Result<Option<Self>, String> {
        let text = |name: &str| {
            get(name)
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
        };
        match text(ENABLE).as_deref() {
            None | Some("false") | Some("0") => return Ok(None),
            Some("true") | Some("1") => {}
            Some(other) => return Err(format!("{ENABLE}: expected true or false, got {other:?}")),
        }
        let number =
            |name: &str, default: Option<i64>, min: i64, max: i64| -> Result<i64, String> {
                let value = match (text(name), default) {
                    (Some(raw), _) => raw
                        .parse::<i64>()
                        .map_err(|_| format!("{name} is not an integer"))?,
                    (None, Some(default)) => default,
                    (None, None) => return Err(format!("{name} is required")),
                };
                if (min..=max).contains(&value) {
                    Ok(value)
                } else {
                    Err(format!("{name} must be between {min} and {max}"))
                }
            };
        Ok(Some(Self {
            min_confidence: number(MIN_CONFIDENCE, None, 1, 100)? as i32,
            assessment_max_age_seconds: number(ASSESSMENT_MAX_AGE_SECONDS, None, 60, 604_800)?
                as i32,
            batch: number(BATCH, Some(5), 1, 20)? as i32,
            ttl_seconds: number(TTL_SECONDS, Some(21_600), 60, 86_400)? as i32,
            spacing: Duration::from_millis(number(SPACING_MILLIS, Some(2000), 1000, 60_000)? as u64),
            cycle: Duration::from_secs(number(CYCLE_SECONDS, Some(60), 30, 3600)? as u64),
        }))
    }

    pub fn from_env() -> Result<Option<Self>, String> {
        Self::from_lookup(|name| std::env::var(name).ok())
    }
}

/// The routing lookup, abstracted so the loop can be tested without the network.
pub trait RoutingLookup {
    fn lookup(
        &self,
        ip: std::net::IpAddr,
    ) -> impl std::future::Future<Output = Result<IpNetworkContext, IpContextError>> + Send;
}

impl RoutingLookup for RipeStatIpContext {
    async fn lookup(&self, ip: std::net::IpAddr) -> Result<IpNetworkContext, IpContextError> {
        RipeStatIpContext::lookup(self, ip).await
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct CycleReport {
    pub targets: usize,
    pub routed: usize,
    pub unrouted: usize,
    pub skipped_non_public: usize,
    pub failed: usize,
    pub refused_by_database: usize,
    pub rate_limited: bool,
    /// The whole loop was still paused by an earlier Retry-After.
    pub paused: bool,
}

/// Short lowercase code for the failure table; never a response body.
fn error_code(error: &IpContextError) -> String {
    match error {
        IpContextError::RateLimited { .. } => "rate_limited".into(),
        IpContextError::Upstream(status) => format!("upstream_{status}"),
        IpContextError::Transport => "transport".into(),
        IpContextError::Rejected(_) => "rejected_response".into(),
    }
}

fn outcome_for(context: &IpNetworkContext, ttl_seconds: i32) -> NetworkContextOutcome {
    match context.prefix {
        None => NetworkContextOutcome::Unrouted { ttl_seconds },
        Some(prefix) => NetworkContextOutcome::Routed {
            prefix: prefix.to_string(),
            origin_asns: context
                .origin_asns
                .iter()
                .map(|asn| i64::from(*asn))
                .collect(),
            rpki: context.rpki.as_str().to_string(),
            ttl_seconds,
        },
    }
}

pub struct IpContextWorker<L: RoutingLookup> {
    store: PostgresStore,
    lookup: L,
    config: IpContextConfig,
    paused_until: Option<Instant>,
}

impl<L: RoutingLookup> IpContextWorker<L> {
    pub fn new(store: PostgresStore, lookup: L, config: IpContextConfig) -> Self {
        Self {
            store,
            lookup,
            config,
            paused_until: None,
        }
    }

    pub fn config(&self) -> &IpContextConfig {
        &self.config
    }

    /// One bounded pass. `now` is injected so pauses are testable.
    pub async fn run_cycle(&mut self, now: Instant) -> anyhow::Result<CycleReport> {
        let mut report = CycleReport::default();
        if self.paused_until.is_some_and(|until| now < until) {
            report.paused = true;
            return Ok(report);
        }
        self.paused_until = None;
        let targets = self
            .store
            .network_context_targets(
                self.config.batch,
                self.config.assessment_max_age_seconds,
                self.config.min_confidence,
            )
            .await?;
        report.targets = targets.len();
        for (index, target) in targets.iter().enumerate() {
            let Ok(ip) = target.raw_ip.parse::<std::net::IpAddr>() else {
                self.store
                    .record_network_context(
                        &target.pseudonym,
                        &NetworkContextOutcome::Skipped {
                            ttl_seconds: 86_400,
                        },
                    )
                    .await?;
                report.skipped_non_public += 1;
                continue;
            };
            if !is_queryable(ip) {
                self.store
                    .record_network_context(
                        &target.pseudonym,
                        &NetworkContextOutcome::Skipped {
                            ttl_seconds: 86_400,
                        },
                    )
                    .await?;
                report.skipped_non_public += 1;
                continue;
            }
            if index > 0 {
                tokio::time::sleep(self.config.spacing).await;
            }
            match self.lookup.lookup(ip).await {
                Ok(context) => {
                    let stored = self
                        .store
                        .record_network_context(
                            &target.pseudonym,
                            &outcome_for(&context, self.config.ttl_seconds),
                        )
                        .await?;
                    if !stored {
                        // Inconsistent with what the database knows (for example a prefix that
                        // does not contain the address): back off like any other failure instead
                        // of asking again on the next cycle.
                        self.store
                            .record_network_context(
                                &target.pseudonym,
                                &NetworkContextOutcome::Failed {
                                    retry_after_seconds: 0,
                                    error: "refused_by_database".into(),
                                },
                            )
                            .await?;
                    }
                    match (stored, context.prefix.is_some()) {
                        (false, _) => report.refused_by_database += 1,
                        (true, true) => report.routed += 1,
                        (true, false) => report.unrouted += 1,
                    }
                }
                Err(error) => {
                    let retry_after = match &error {
                        IpContextError::RateLimited {
                            retry_after_seconds,
                        } => i32::try_from(*retry_after_seconds).unwrap_or(3600),
                        _ => 0,
                    };
                    self.store
                        .record_network_context(
                            &target.pseudonym,
                            &NetworkContextOutcome::Failed {
                                retry_after_seconds: retry_after,
                                error: error_code(&error),
                            },
                        )
                        .await?;
                    report.failed += 1;
                    if let IpContextError::RateLimited {
                        retry_after_seconds,
                    } = error
                    {
                        self.paused_until = Some(now + Duration::from_secs(retry_after_seconds));
                        report.rate_limited = true;
                        break; // stop for this cycle; the rest wait for the pause to end
                    }
                }
            }
        }
        info!(
            targets = report.targets,
            routed = report.routed,
            unrouted = report.unrouted,
            skipped = report.skipped_non_public,
            failed = report.failed,
            refused = report.refused_by_database,
            rate_limited = report.rate_limited,
            "ip routing-context cycle finished"
        );
        Ok(report)
    }
}

/// Run forever (until the task is dropped). Errors are logged, never fatal.
pub async fn run_forever(store: PostgresStore, config: IpContextConfig) {
    let cycle = config.cycle;
    let lookup = match RipeStatIpContext::new("clawforge") {
        Ok(lookup) => lookup,
        Err(error) => {
            warn!(%error, "ip routing-context disabled: client could not be built");
            return;
        }
    };
    let mut worker = IpContextWorker::new(store, lookup, config);
    let mut ticks = tokio::time::interval(cycle);
    ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        ticks.tick().await;
        if let Err(error) = worker.run_cycle(Instant::now()).await {
            warn!(%error, "ip routing-context cycle failed");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn lookup(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        move |name| map.get(name).cloned()
    }

    #[test]
    fn disabled_unless_explicitly_enabled() {
        assert_eq!(IpContextConfig::from_lookup(lookup(&[])), Ok(None));
        assert_eq!(
            IpContextConfig::from_lookup(lookup(&[(ENABLE, "false")])),
            Ok(None)
        );
        assert!(IpContextConfig::from_lookup(lookup(&[(ENABLE, "yes")])).is_err());
    }

    #[test]
    fn enabling_requires_the_relevance_settings_and_bounds_the_politeness_settings() {
        let base = [
            (ENABLE, "true"),
            (MIN_CONFIDENCE, "70"),
            (ASSESSMENT_MAX_AGE_SECONDS, "3600"),
        ];
        let config = IpContextConfig::from_lookup(lookup(&base))
            .unwrap()
            .unwrap();
        assert_eq!((config.batch, config.ttl_seconds), (5, 21_600));
        assert_eq!(config.spacing, Duration::from_millis(2000));
        assert!(
            IpContextConfig::from_lookup(lookup(&[(ENABLE, "true"), (MIN_CONFIDENCE, "70")]))
                .is_err()
        );
        assert!(IpContextConfig::from_lookup(lookup(&[
            (ENABLE, "true"),
            (ASSESSMENT_MAX_AGE_SECONDS, "3600")
        ]))
        .is_err());
        for (name, bad) in [
            (MIN_CONFIDENCE, "0"),
            (MIN_CONFIDENCE, "101"),
            (ASSESSMENT_MAX_AGE_SECONDS, "59"),
            (BATCH, "0"),
            (BATCH, "21"),
            (TTL_SECONDS, "59"),
            (TTL_SECONDS, "86401"),
            (SPACING_MILLIS, "999"),
            (CYCLE_SECONDS, "29"),
            (BATCH, "many"),
        ] {
            let mut pairs = base.to_vec();
            pairs.push((name, bad));
            assert!(
                IpContextConfig::from_lookup(lookup(&pairs)).is_err(),
                "{name}={bad}"
            );
        }
    }

    #[test]
    fn error_codes_are_short_and_never_carry_response_content() {
        for error in [
            IpContextError::RateLimited {
                retry_after_seconds: 9,
            },
            IpContextError::Upstream(503),
            IpContextError::Transport,
            IpContextError::Rejected("anything at all, even <script> text"),
        ] {
            let code = error_code(&error);
            assert!(
                code.len() <= 40
                    && code
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'),
                "{code}"
            );
        }
    }
}
