# Event delivery claim

Consumers (correlation, security engine, ...) take their work from `event_delivery`
through `PostgresStore::claim_event_deliveries`.

## Claim order and cost

1. Stale in-flight rows first (`status='processing'`, lease of 10 minutes expired, fewer
   than 5 attempts). They are few and use `event_delivery_claim_idx`. A deep backlog can
   therefore never starve a stuck delivery.
2. Ready rows fill the remaining slots, oldest first (`status IN ('pending','failed')`,
   `available_at <= now`, fewer than 5 attempts), read from the partial index
   `event_delivery_ready_idx (consumer_id, created_at) WHERE status IN ('pending','failed')`
   (migration 0065). A claim reads as many rows as it takes, however deep the backlog.
3. Only the locked ids are joined to `events`. Locks are taken on `event_delivery` alone
   (`FOR UPDATE OF d SKIP LOCKED`); the consumer roles only have `SELECT` on `events`.

Measured on a 400 000-row backlog (isolated PostgreSQL, same data for both): old statement
816 ms (hash join of both tables, external sort), new statement 0.5 ms. On production the old
statement took ~2.2 s per poll (7.9 M rows, ~340 k ready for one consumer) and read all of
`events`.

## Production: build the index before the migration

The migration uses `CREATE INDEX IF NOT EXISTS`. On the 3 GB production table build it first
without blocking writers, check it is valid, then run the migration:

```sql
CREATE INDEX CONCURRENTLY IF NOT EXISTS event_delivery_ready_idx
  ON event_delivery (consumer_id, created_at) WHERE status IN ('pending', 'failed');
SELECT indisvalid FROM pg_index WHERE indexrelid = 'event_delivery_ready_idx'::regclass;
```

A failed concurrent build leaves an invalid index: `DROP INDEX CONCURRENTLY event_delivery_ready_idx;`
and build again. Rolling back to 1.1.x keeps the index (harmless); the ledger entry 65 is removed by
`scripts/release/rollback-1.2-to-1.1.sql`.

## The `analyzer` consumer

`publish_event` fans every event out to every *enabled* row of `event_consumers`. The analyzer
service runs with `CLAWFORGE_ANALYZER_EVENT_CONSUMER=false`, yet its consumer row is enabled,
so production holds ~1.58 M deliveries that nobody claims (growing ~2/s). They cost storage, not
claim time (the ready index is per consumer). Nothing is deleted or marked consumed by Clawforge.
Hazard: enabling the analyzer consumer later would hand it the whole backlog from 2026-09-23 on.
Decide that explicitly (archive the old rows, or start the consumer from a cut-off) before enabling it.
To stop the growth meanwhile (reversible): `UPDATE event_consumers SET enabled=false WHERE name='analyzer';`
(`ensure_event_consumer` sets it back to true when the consumer is started).
