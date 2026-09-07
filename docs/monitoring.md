# Monitoring

`GET /metrics` exposes Prometheus text format. It includes provider sync and
error counters, per-provider sync status, indicator and risk-event totals,
BGP changes, database availability, and a worker heartbeat gauge. The worker
updates its PostgreSQL heartbeat on every scheduler tick; PostgreSQL remains
the source of truth.

Use `/health` for process/configuration checks, `/ready` for PostgreSQL and
migration readiness, and `/version` for the running release and schema status.
Alert when `clawforge_worker_up` or `clawforge_database_up` is zero, provider
status is zero, or provider errors increase unexpectedly.
