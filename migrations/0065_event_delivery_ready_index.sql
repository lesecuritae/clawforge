-- The delivery claim ("oldest ready delivery of this consumer first") used to sort the
-- whole backlog on every poll: the claim query ORs pending/failed with stale-processing
-- rows, which the (consumer_id, status, available_at, created_at) index cannot return in
-- created_at order. On production (7.9 M rows, 340 k ready for one consumer) every poll
-- cost ~2.2 s and a seq scan of events. This partial index returns exactly the ready rows
-- of one consumer in arrival order, so a claim reads only as many rows as it takes.
--
-- Production: on a large table build it first without blocking writers, then let this
-- migration find it present:
--   CREATE INDEX CONCURRENTLY IF NOT EXISTS event_delivery_ready_idx
--     ON event_delivery (consumer_id, created_at) WHERE status IN ('pending', 'failed');
--   (and check pg_index.indisvalid before running the migration)
-- Fresh and test databases build it here in milliseconds.
CREATE INDEX IF NOT EXISTS event_delivery_ready_idx
    ON event_delivery (consumer_id, created_at)
    WHERE status IN ('pending', 'failed');
