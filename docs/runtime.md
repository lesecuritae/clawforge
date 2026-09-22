# Runtime and operations

`compose.yml` runs `clawforge-api`, `clawforge-worker`, `clawforge-frontend`, PostgreSQL, and the scheduled `clawforge-backup` service. Redis is present only under the optional `cache` profile. A one-shot migration service applies the shared sqlx migration set with the owner account, followed by an idempotent role-provisioning job. Each database-backed runtime service then uses its own restricted account; the backup account is read-only. The frontend waits for API readiness. See [deployment.md](deployment.md) and [configuration.md](configuration.md) for operations.

When `REDIS_URL` is configured, the worker uses a short-lived Redis lock to prevent duplicate scheduler runs across worker replicas. Redis is never the source of truth for providers, indicators, network records, risk history, or audit events; those remain in PostgreSQL.

The API exposes read-only operational views at `/intelligence/providers`,
`/intelligence/status`, and `/intelligence/indicators`, plus `/network/asn`,
`/network/bgp`, `/network/rpki`, and `/network/trust`. Each record includes its
source, timestamp, status, confidence or trust context, data age, and the
persisted assessment. Prometheus-compatible counters and gauges are available
at `/metrics`.

Provider, network, risk, and trusted-infrastructure changes are persisted as
typed `audit_events` with a timestamp, source, severity, reason, and structured
details. A single feed or event is never used as a block decision.

Configuration is supplied through environment variables. Keep `.env` and database credentials outside version control. PostgreSQL's named volume is the primary persistence layer; take a database dump before upgrades and preserve the configuration and trusted-network registry together.

Run `scripts/test-postgres.sh` for an isolated PostgreSQL 16 migration and
least-privilege test. It checks allowed service writes and rejects cross-domain
writes, credential-table reads, audit mutation, and backup writes. The
backup/restore script validates a real dump and restore cycle.
