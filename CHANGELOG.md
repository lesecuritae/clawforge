# Changelog

## [Unreleased]

- Added PostgreSQL-backed notification channels, rules, retries, and internal delivery worker.
- Added the canonical event backbone with consumer delivery, deduplication, retry/dead-letter handling, internal service authentication, and event metrics.
- Added optional event consumption for the notifier and analyzer services.

## [0.1.0] - 2026-09-07

- Rust API and worker runtime with PostgreSQL/sqlx migrations.
- Threat, ASN, BGP, RPKI, trust, risk, and operational event persistence.
- Operational API views and Prometheus-compatible metrics.
- Production backup, restore, update, migration, and container-hardening workflows.
- Role-aware global and endpoint-specific API rate limits with 429 retry headers and audit events.

[Unreleased]: https://github.com/lesecuritae/clawforge/compare/v0.1.0...HEAD
