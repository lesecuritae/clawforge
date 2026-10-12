//! Exact, bounded metrics collection. Unknown samples are omitted, never fabricated.
use crate::PostgresStore;
use sqlx::{postgres::PgRow, Connection, Row};
use std::time::{Duration, Instant};

const CACHE_TTL: Duration = Duration::from_secs(30);
const COLLECTION_BUDGET: Duration = Duration::from_secs(3);
pub(crate) struct CachedMetrics {
    captured: Instant,
    body: String,
}

impl PostgresStore {
    pub async fn metrics_text(&self) -> anyhow::Result<String> {
        // Clones share this lock/cache: only one collector may touch PostgreSQL.
        let mut cache = self.metrics_cache.lock().await;
        if cache
            .as_ref()
            .is_none_or(|entry| entry.captured.elapsed() >= CACHE_TTL)
        {
            let body = self.collect_bounded_metrics().await;
            *cache = Some(CachedMetrics {
                captured: Instant::now(),
                body,
            });
        }
        let entry = cache.as_ref().expect("collector populated cache");
        Ok(format!("{}# TYPE clawforge_metrics_cache_age_seconds gauge\nclawforge_metrics_cache_age_seconds {:.6}\n", entry.body, entry.captured.elapsed().as_secs_f64()))
    }

    async fn metrics_query(&self, sql: &str, deadline: Instant) -> Option<Vec<PgRow>> {
        let remaining = deadline.checked_duration_since(Instant::now())?;
        let mut connection =
            tokio::time::timeout(remaining.min(Duration::from_secs(1)), self.pool.acquire())
                .await
                .ok()?
                .ok()?;
        let remaining = deadline.checked_duration_since(Instant::now())?;
        // Enforce the remaining budget on BEGIN, settings, fetch AND rollback;
        // statement_timeout also cancels the server statement on normal timeout.
        let result = tokio::time::timeout(remaining, async {
            let mut tx = connection.begin().await?;
            sqlx::query("SET TRANSACTION READ ONLY")
                .execute(&mut *tx)
                .await?;
            let statement_ms = deadline
                .saturating_duration_since(Instant::now())
                .as_millis()
                .clamp(1, 200);
            let lock_ms = statement_ms.min(100);
            sqlx::query(
                "SELECT set_config('statement_timeout',$1,true),set_config('lock_timeout',$2,true)",
            )
            .bind(format!("{statement_ms}ms"))
            .bind(format!("{lock_ms}ms"))
            .execute(&mut *tx)
            .await?;
            let result = sqlx::query(sql).fetch_all(&mut *tx).await;
            tx.rollback().await?;
            result
        })
        .await;
        match result {
            Ok(Ok(rows)) => Some(rows),
            _ => {
                // A cancelled future may have queued rollback without completing
                // it. Hard-drop the detached socket: never return uncertain state
                // or a network-stalled connection to the shared pool.
                drop(connection.detach());
                None
            }
        }
    }

    async fn collect_bounded_metrics(&self) -> String {
        let started = Instant::now();
        let deadline = started + COLLECTION_BUDGET;
        let mut body = String::new();
        let mut omitted = 0_u32;
        // Cheap current liveness comes first; historical aggregates cannot starve it.
        for (name, label, sql, string_value) in [
            ("clawforge_provider_sync_status", "provider", "SELECT p.id AS label, COALESCE(s.state, 'never') AS state FROM providers p LEFT JOIN provider_status s ON s.provider_id = p.id ORDER BY p.id", true),
            ("clawforge_event_consumer_up", "consumer", "SELECT name AS label, CASE WHEN last_heartbeat_at > NOW() - INTERVAL '2 minutes' THEN 1 ELSE 0 END AS up FROM event_consumers ORDER BY name", false),
            ("clawforge_component_up", "component", "SELECT component AS label, CASE WHEN state='running' AND updated_at > NOW() - INTERVAL '2 minutes' THEN 1 ELSE 0 END AS up FROM runtime_status ORDER BY component", false),
        ] {
            if let Some(rows) = self.metrics_query(sql, deadline).await {
                body.push_str(&format!("# TYPE {name} gauge\n"));
                for row in rows {
                    let text = row.get::<String,_>("label");
                    let value = if string_value { i32::from(matches!(row.get::<String,_>("state").as_str(), "ok" | "running")) } else { row.get::<i32,_>("up") };
                    body.push_str(&format!("{name}{{{label}=\"{}\"}} {value}\n", escape_label(&text)));
                }
            } else { omitted += 1; }
        }
        for (name, kind, sql, floating) in [
            ("clawforge_worker_up", "gauge", "SELECT COUNT(*) FROM runtime_status WHERE component = 'worker' AND state = 'running' AND last_heartbeat_at > NOW() - INTERVAL '2 minutes'", false),
            ("clawforge_execution_workers_healthy", "gauge", "SELECT COUNT(*) FROM execution_workers WHERE status IN ('healthy','degraded') AND last_heartbeat_at > NOW() - INTERVAL '2 minutes'", false),
            ("clawforge_incidents_active", "gauge", "SELECT COUNT(*) FROM incidents WHERE status NOT IN ('resolved','closed')", false),
            ("clawforge_alerts_open", "gauge", "SELECT COUNT(*) FROM alerts WHERE status='open'", false),
            ("clawforge_provider_quality_average", "gauge", "SELECT COALESCE(AVG(quality_score), 0)::float8 FROM providers", true),
            ("clawforge_indicators_total", "gauge", "SELECT COUNT(*) FROM indicators", false),
            ("clawforge_risk_events_total", "counter", "SELECT COUNT(*) FROM risk_history", false),
            ("clawforge_provider_sync_total", "counter", "SELECT COUNT(*) FROM audit_events WHERE event_type = 'provider_sync'", false),
            ("clawforge_provider_errors_total", "counter", "SELECT COUNT(*) FROM audit_events WHERE event_type = 'provider_error'", false),
            ("clawforge_bgp_changes_total", "counter", "SELECT COUNT(*) FROM audit_events WHERE event_type = 'bgp_change'", false),
            ("clawforge_agent_api_access_total", "counter", "SELECT COUNT(*) FROM audit_events WHERE actor LIKE 'agent:%' AND action = 'agent_api_read'", false),
            ("clawforge_actions_total", "counter", "SELECT COUNT(*) FROM execution_metrics", false),
            ("clawforge_action_errors_total", "counter", "SELECT COUNT(*) FROM execution_metrics WHERE status IN ('failed','timeout')", false),
            ("clawforge_execution_duration", "gauge", "SELECT COALESCE(AVG(duration_ms),0)::float8 FROM execution_metrics", true),
            ("clawforge_policy_denials_total", "counter", "SELECT COUNT(*) FROM audit_events WHERE action LIKE '%denied%' AND (resource LIKE '%action%' OR resource LIKE '%execution%')", false),
            ("clawforge_events_created_total", "counter", "SELECT COUNT(*) FROM events", false),
            ("clawforge_events_processed_total", "counter", "SELECT COUNT(*) FROM event_delivery WHERE status='processed'", false),
            ("clawforge_events_failed_total", "counter", "SELECT COUNT(*) FROM event_delivery WHERE status IN ('failed','dead')", false),
            ("clawforge_event_queue_size", "gauge", "SELECT COUNT(*) FROM event_delivery WHERE status IN ('pending','processing')", false),
            ("clawforge_event_processing_duration_seconds", "gauge", "SELECT COALESCE(AVG(EXTRACT(EPOCH FROM (processed_at - processing_started_at))), 0)::float8 FROM event_delivery WHERE status='processed' AND processed_at IS NOT NULL AND processing_started_at IS NOT NULL", true),
            ("clawforge_correlations_total", "gauge", "SELECT COUNT(*) FROM event_relationships", false),
        ] {
            if let Some(rows) = self.metrics_query(sql, deadline).await {
                if let Some(row) = rows.first() {
                    if floating { sample(&mut body,name,kind,row.get::<f64,_>(0)); }
                    else { sample(&mut body,name,kind,row.get::<i64,_>(0)); }
                } else { omitted += 1; }
            } else { omitted += 1; }
        }
        // A completed SQL collection path proves connectivity; no false healthy
        // database sample is emitted when all samples were unavailable.
        if omitted < 24 {
            sample(&mut body, "clawforge_database_up", "gauge", 1);
        }
        sample(
            &mut body,
            "clawforge_metrics_collection_partial",
            "gauge",
            u8::from(omitted > 0),
        );
        sample(
            &mut body,
            "clawforge_metrics_omitted_samples",
            "gauge",
            omitted,
        );
        sample(
            &mut body,
            "clawforge_metrics_collection_duration_seconds",
            "gauge",
            started.elapsed().as_secs_f64(),
        );
        body
    }
}
fn escape_label(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}
fn sample(body: &mut String, name: &str, kind: &str, value: impl std::fmt::Display) {
    body.push_str(&format!("# TYPE {name} {kind}\n{name} {value}\n"));
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn labels_escape_prometheus_newline_quote_and_backslash() {
        assert_eq!(escape_label("a\n\"\\b"), "a\\n\\\"\\\\b");
    }
    #[test]
    fn exact_sample_preserves_name_type_and_value() {
        let mut body = String::new();
        sample(&mut body, "clawforge_correlations_total", "gauge", 42_i64);
        assert_eq!(
            body,
            "# TYPE clawforge_correlations_total gauge\nclawforge_correlations_total 42\n"
        );
    }
    #[tokio::test]
    #[ignore = "requires an isolated migrated PostgreSQL fixture"]
    async fn metrics_bounded_singleflight_timeout_omission_and_recovery() -> anyhow::Result<()> {
        let store = PostgresStore::connect(&std::env::var("CLAWFORGE_TEST_DATABASE_URL")?).await?;
        let events = [uuid::Uuid::new_v4(), uuid::Uuid::new_v4()];
        for event in events {
            sqlx::query("INSERT INTO events(event_id,event_type,source,severity,occurred_at,dedupe_key) VALUES($1,'test','metrics-fixture','info',NOW(),$2)").bind(event).bind(event.to_string()).execute(store.pool()).await?;
        }
        sqlx::query("INSERT INTO event_relationships(id,event_id,related_event_id,relation_type,confidence,reason) VALUES($1,$2,$3,'test',100,'fixture')").bind(uuid::Uuid::new_v4()).bind(events[0]).bind(events[1]).execute(store.pool()).await?;
        let expected: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM event_relationships")
            .fetch_one(store.pool())
            .await?;
        let exact = store.metrics_text().await?;
        assert!(exact.contains(&format!("clawforge_correlations_total {expected}\n")));
        assert!(exact.contains("clawforge_metrics_collection_partial 0\n"));
        assert!(exact.contains("clawforge_metrics_omitted_samples 0\n"));
        // Every clone shares the exact same collection generation.
        let generation = store.metrics_cache.lock().await.as_ref().unwrap().captured;
        let clone = store.clone();
        assert_eq!(
            exact.split("# TYPE clawforge_metrics_cache_age").next(),
            clone
                .metrics_text()
                .await?
                .split("# TYPE clawforge_metrics_cache_age")
                .next()
        );
        assert_eq!(
            generation,
            clone.metrics_cache.lock().await.as_ref().unwrap().captured
        );
        let mut locked = store.pool().begin().await?;
        sqlx::query("LOCK TABLE event_relationships IN ACCESS EXCLUSIVE MODE")
            .execute(&mut *locked)
            .await?;
        store.metrics_cache.lock().await.as_mut().unwrap().captured -= CACHE_TTL;
        let started = Instant::now();
        let (a, b, c) = tokio::join!(
            store.metrics_text(),
            clone.metrics_text(),
            store.metrics_text()
        );
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "locked collection must remain bounded"
        );
        let a = a?;
        let b = b?;
        let c = c?;
        for body in [&a, &b, &c] {
            assert!(!body
                .lines()
                .any(|line| line.starts_with("clawforge_correlations_total ")));
            assert!(!body.contains("# TYPE clawforge_correlations_total"));
            assert!(body.contains("clawforge_metrics_collection_partial 1\n"));
            assert!(body.contains("clawforge_metrics_omitted_samples 1\n"));
            assert!(body.contains("clawforge_worker_up "));
        }
        assert_eq!(
            a.split("# TYPE clawforge_metrics_cache_age").next(),
            b.split("# TYPE clawforge_metrics_cache_age").next()
        );
        assert_eq!(
            b.split("# TYPE clawforge_metrics_cache_age").next(),
            c.split("# TYPE clawforge_metrics_cache_age").next()
        );
        locked.rollback().await?;
        // Server cancellation, not merely client future timeout: no sleeping backend survives.
        let started = Instant::now();
        assert!(store
            .metrics_query("SELECT pg_sleep(5)", Instant::now() + COLLECTION_BUDGET)
            .await
            .is_none());
        assert!(started.elapsed() < Duration::from_secs(2));
        // The overall deadline must win even before PostgreSQL's 200ms timeout.
        let started = Instant::now();
        assert!(store
            .metrics_query(
                "SELECT pg_sleep(5)",
                Instant::now() + Duration::from_millis(30)
            )
            .await
            .is_none());
        assert!(
            started.elapsed() < Duration::from_millis(150),
            "remaining collection deadline must bound SQL and cleanup"
        );
        // Connection disposal can race server disconnect processing briefly.
        tokio::time::sleep(Duration::from_millis(100)).await;
        let active: i64=sqlx::query_scalar("SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND state='active' AND query='SELECT pg_sleep(5)'").fetch_one(store.pool()).await?;
        assert_eq!(active, 0);
        let before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM event_relationships")
            .fetch_one(store.pool())
            .await?;
        assert!(
            store
                .metrics_query(
                    "DELETE FROM event_relationships",
                    Instant::now() + COLLECTION_BUDGET
                )
                .await
                .is_none(),
            "metric transactions must be read only"
        );
        let after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM event_relationships")
            .fetch_one(store.pool())
            .await?;
        assert_eq!(before, after);
        let statement: String = sqlx::query_scalar("SHOW statement_timeout")
            .fetch_one(store.pool())
            .await?;
        let lock: String = sqlx::query_scalar("SHOW lock_timeout")
            .fetch_one(store.pool())
            .await?;
        assert_eq!(statement, "0");
        assert_eq!(lock, "0");
        store.metrics_cache.lock().await.as_mut().unwrap().captured -= CACHE_TTL;
        let recovered = store.metrics_text().await?;
        assert!(recovered.contains(&format!("clawforge_correlations_total {expected}\n")));
        assert!(recovered.contains("clawforge_metrics_collection_partial 0\n"));
        for event in events {
            sqlx::query("DELETE FROM events WHERE event_id=$1")
                .bind(event)
                .execute(store.pool())
                .await?;
        }
        Ok(())
    }
}
