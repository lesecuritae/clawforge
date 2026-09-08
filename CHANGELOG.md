# Changelog

## [Unreleased]

- Added PostgreSQL-backed notification channels, rules, retries, and internal delivery worker.
- Added the canonical event backbone with consumer delivery, deduplication, retry/dead-letter handling, internal service authentication, and event metrics.
- Added optional event consumption for the notifier and analyzer services.
- Added read-only visualization APIs and an SVG-based frontend view for event timelines, network relationships, incident correlations, and trusted infrastructure.
- Expanded the frontend into an operations dashboard with runtime cards, Prometheus monitoring values, filtered event streaming, incident relationship details, and richer ASN/BGP/RPKI tables.
- Added provider quality and failure metadata, the read-only provider status and operations summary APIs, and matching MCP tools.
- Added an Operations Summary dashboard view, source/time incident filters, audit explorer filters, and retention documentation.

## [0.3.0] - 2026-09-08

- Validated the production OpenClaw connection through the isolated,
  streamable-HTTP MCP adapter with all 14 read-only tools discoverable.
- Added the read-only Operations Agent role, scoped Agent API credentials, and
  secret-injected example configuration.
- Added live MCP, Agent API audit, correlation, and operational validation
  documentation without enabling provider feeds or write actions.

## [0.1.0] - 2026-09-07

- Rust API and worker runtime with PostgreSQL/sqlx migrations.
- Threat, ASN, BGP, RPKI, trust, risk, and operational event persistence.
- Operational API views and Prometheus-compatible metrics.
- Production backup, restore, update, migration, and container-hardening workflows.
- Role-aware global and endpoint-specific API rate limits with 429 retry headers and audit events.

[Unreleased]: https://github.com/lesecuritae/clawforge/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/lesecuritae/clawforge/releases/tag/v0.3.0
