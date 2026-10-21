//! Current reputation and routing context of a pseudonymized source (migration
//! 0063). Everything is evaluated inside the database; the raw address is only
//! ever returned to the worker's enrichment loop, which needs it to ask a public
//! routing API, and `Debug` redacts it.
use crate::PostgresStore;
use anyhow::{bail, Result};
use chrono::{DateTime, Utc};
use sqlx::Row;

/// The current view of one source. All "listed" flags are computed now against
/// unexpired reputation indicators; `resolved == false` means there is no
/// current view at all (no unexpired single-host resolution), which is not the
/// same as "not listed".
#[derive(Debug, Clone, PartialEq)]
pub struct SourceIntel {
    pub resolved: bool,
    pub ip: Option<ListingHit>,
    pub asn: Option<AsnListingHit>,
    pub context: Option<RoutingContext>,
    pub bgp_anomaly: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ListingHit {
    pub source: String,
    pub confidence: i16,
    pub last_seen: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AsnListingHit {
    pub asn: i64,
    pub hit: ListingHit,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RoutingContext {
    pub prefix: String,
    pub origin_asns: Vec<i64>,
    pub rpki: String,
    pub fetched_at: DateTime<Utc>,
}

impl ListingHit {
    /// Fresh and confident enough to count as corroborating evidence.
    pub fn is_usable(&self, min_confidence: i16, max_age_seconds: i64, now: DateTime<Utc>) -> bool {
        let age = (now - self.last_seen).num_seconds();
        self.confidence >= min_confidence && (0..=max_age_seconds).contains(&age)
    }
}

impl SourceIntel {
    /// The listing that qualifies as independent reputation evidence, preferring
    /// the address itself over its origin ASN: `("ip" | "asn", hit)`.
    pub fn qualifying_listing(
        &self,
        min_confidence: i16,
        max_age_seconds: i64,
        now: DateTime<Utc>,
    ) -> Option<(&'static str, &ListingHit)> {
        if let Some(hit) = self
            .ip
            .as_ref()
            .filter(|h| h.is_usable(min_confidence, max_age_seconds, now))
        {
            return Some(("ip", hit));
        }
        self.asn
            .as_ref()
            .map(|a| &a.hit)
            .filter(|h| h.is_usable(min_confidence, max_age_seconds, now))
            .map(|hit| ("asn", hit))
    }

    /// Routing facts for the decision record and the approver; never the address.
    pub fn routing_json(&self) -> serde_json::Value {
        match &self.context {
            Some(c) => serde_json::json!({
                "prefix": c.prefix, "origin_asns": c.origin_asns, "rpki": c.rpki,
                "bgp_anomaly": self.bgp_anomaly,
            }),
            None => serde_json::json!({ "context": "none", "bgp_anomaly": self.bgp_anomaly }),
        }
    }
}

/// A source the worker should look up. `Debug` hides the address.
#[derive(Clone, PartialEq, Eq)]
pub struct NetworkContextTarget {
    pub pseudonym: String,
    pub raw_ip: String,
}

impl std::fmt::Debug for NetworkContextTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NetworkContextTarget")
            .field("pseudonym", &self.pseudonym)
            .field("raw_ip", &"<redacted>")
            .finish()
    }
}

/// One lookup outcome to store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkContextOutcome {
    Routed {
        prefix: String,
        origin_asns: Vec<i64>,
        rpki: String,
        ttl_seconds: i32,
    },
    Unrouted {
        ttl_seconds: i32,
    },
    /// Not a publicly routable address: never sent to a third party.
    Skipped {
        ttl_seconds: i32,
    },
    /// `error` is a short lowercase code (`[a-z0-9_ :-]`), never a response body.
    Failed {
        retry_after_seconds: i32,
        error: String,
    },
}

impl PostgresStore {
    pub async fn current_source_intel(&self, pseudonym: &str) -> Result<SourceIntel> {
        let row = sqlx::query("SELECT * FROM clawforge_current_source_intel($1)")
            .bind(pseudonym)
            .fetch_one(self.pool())
            .await?;
        let hit =
            |source: Option<String>, confidence: Option<i16>, last_seen: Option<DateTime<Utc>>| {
                match (source, confidence, last_seen) {
                    (Some(source), Some(confidence), Some(last_seen)) => Some(ListingHit {
                        source,
                        confidence,
                        last_seen,
                    }),
                    _ => None,
                }
            };
        let ip = if row.get::<bool, _>("ip_listed") {
            hit(
                row.get("ip_source"),
                row.get("ip_confidence"),
                row.get("ip_last_seen"),
            )
        } else {
            None
        };
        let asn = if row.get::<bool, _>("asn_listed") {
            let asn: Option<i64> = row.get("asn");
            hit(
                row.get("asn_source"),
                row.get("asn_confidence"),
                row.get("asn_last_seen"),
            )
            .zip(asn)
            .map(|(hit, asn)| AsnListingHit { asn, hit })
        } else {
            None
        };
        let context = match row.get::<Option<String>, _>("context_status").as_deref() {
            Some("ok") => Some(RoutingContext {
                prefix: row
                    .get::<Option<String>, _>("prefix_text")
                    .unwrap_or_default(),
                origin_asns: row
                    .get::<Option<Vec<i64>>, _>("origin_asns")
                    .unwrap_or_default(),
                rpki: row.get::<Option<String>, _>("rpki").unwrap_or_default(),
                fetched_at: row
                    .get::<Option<DateTime<Utc>>, _>("context_fetched_at")
                    .unwrap_or_else(Utc::now),
            }),
            _ => None,
        };
        Ok(SourceIntel {
            resolved: row.get("resolved"),
            ip,
            asn,
            context,
            bgp_anomaly: row.get("bgp_anomaly"),
        })
    }

    pub async fn network_context_targets(
        &self,
        limit: i32,
        assessment_max_age_seconds: i32,
        min_confidence: i32,
    ) -> Result<Vec<NetworkContextTarget>> {
        let rows = sqlx::query(
            "SELECT pseudonym, raw_ip FROM clawforge_network_context_targets($1,$2,$3)",
        )
        .bind(limit)
        .bind(assessment_max_age_seconds)
        .bind(min_confidence)
        .fetch_all(self.pool())
        .await?;
        Ok(rows
            .into_iter()
            .map(|row| NetworkContextTarget {
                pseudonym: row.get("pseudonym"),
                raw_ip: row.get("raw_ip"),
            })
            .collect())
    }

    /// `Ok(false)`: the database refused the record (no live resolution, a prefix
    /// that does not contain the address, out-of-range values) - nothing stored.
    pub async fn record_network_context(
        &self,
        pseudonym: &str,
        outcome: &NetworkContextOutcome,
    ) -> Result<bool> {
        let (status, prefix, origins, rpki, ttl, retry, error): (
            &str,
            Option<&str>,
            Vec<i64>,
            &str,
            i32,
            i32,
            Option<&str>,
        ) = match outcome {
            NetworkContextOutcome::Routed {
                prefix,
                origin_asns,
                rpki,
                ttl_seconds,
            } => (
                "ok",
                Some(prefix),
                origin_asns.clone(),
                rpki,
                *ttl_seconds,
                0,
                None,
            ),
            NetworkContextOutcome::Unrouted { ttl_seconds } => (
                "unrouted",
                None,
                Vec::new(),
                "not_checked",
                *ttl_seconds,
                0,
                None,
            ),
            NetworkContextOutcome::Skipped { ttl_seconds } => (
                "skipped",
                None,
                Vec::new(),
                "not_checked",
                *ttl_seconds,
                0,
                None,
            ),
            NetworkContextOutcome::Failed {
                retry_after_seconds,
                error,
            } => {
                if error.is_empty()
                    || error.len() > 120
                    || !error.bytes().all(|b| {
                        b.is_ascii_lowercase() || b.is_ascii_digit() || b" _:-".contains(&b)
                    })
                {
                    bail!("network context error code must be short lowercase text");
                }
                (
                    "failed",
                    None,
                    Vec::new(),
                    "not_checked",
                    0,
                    *retry_after_seconds,
                    Some(error.as_str()),
                )
            }
        };
        Ok(sqlx::query_scalar(
            "SELECT clawforge_record_network_context($1,$2,$3::cidr,$4,$5,'ripestat',$6,$7,$8)",
        )
        .bind(pseudonym)
        .bind(status)
        .bind(prefix)
        .bind(&origins)
        .bind(rpki)
        .bind(ttl)
        .bind(retry)
        .bind(error)
        .fetch_one(self.pool())
        .await?)
    }
}
