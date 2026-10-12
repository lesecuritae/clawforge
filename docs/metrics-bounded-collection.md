# Bounded exact Prometheus collection

The previous `/metrics` collector executed full historical COUNT/AVG queries on every scrape. Prometheus scraping every 15 seconds could abandon HTTP requests while PostgreSQL continued scanning large tables. Parallel PostgreSQL workers are not separate HTTP callers; diagnosis must distinguish `backend_type` and `leader_pid`.

The storage collector now shares a singleflight mutex and 30-second cache across `PostgresStore` clones. It retains all existing metric names, types and exact SQL definitions. Current provider, consumer and component liveness is collected before historical aggregates.

Each query runs in a read-only transaction with PostgreSQL `statement_timeout` at most 200ms and `lock_timeout` at most 100ms, both clipped to the remaining collection deadline. Pool acquisition is bounded to one second or the remaining collection budget. The remaining three-second deadline bounds transaction begin, session settings, fetch and rollback as well as admission. If timeout or failure leaves connection state uncertain, its detached socket is hard-dropped instead of returned to the pool. Transaction rollback prevents settings from leaking to other users of the pool. Client disconnection cannot leave an unbounded metrics query running.

Unknown or timed-out samples are omitted, including their TYPE declaration. They are never replaced by zero or an estimate. Cached samples retain their exact values from collection time. These new gauges explain availability and freshness:

- `clawforge_metrics_collection_partial`: one when any scalar or labelled group was unavailable.
- `clawforge_metrics_omitted_samples`: number of unavailable scalar samples or labelled groups (not an invented count of missing labels).
- `clawforge_metrics_collection_duration_seconds`: elapsed time of the cached collection.
- `clawforge_metrics_cache_age_seconds`: age since completion of that collection.

`clawforge_database_up` is emitted only if at least one database sample or labelled group was collected. A completely unavailable database yields partial/omission metadata without a false healthy sample. API process counters remain uncached in the API handler. Metrics authorization remains unchanged.

A historically expensive exact count may remain absent until it can complete within the query budget. Consumers should alert on collection partiality and sample absence instead of interpreting absent time series as zero. Long-term aggregates should eventually be maintained transactionally or through a separately validated aggregation design; this change does not substitute approximate counts under old names.

## Verification

Unit tests cover exact Prometheus name/type/value rendering and escaping. The actual isolated PostgreSQL test `metrics::tests::metrics_bounded_singleflight_timeout_omission_and_recovery` covers an exact relationship fixture count, shared clone cache, concurrent scrapes during an exclusive relation lock, bounded completion, omission rather than false zero, unaffected worker metric, PostgreSQL cancellation of a sleeping query, earlier overall-deadline cancellation with connection disposal, prohibited writes, transaction-local setting restoration, and successful exact collection after recovery.

No migrations, database role changes, production config changes, or releases are included in this implementation.
