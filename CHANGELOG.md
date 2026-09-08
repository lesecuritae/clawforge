# Changelog

## [Unreleased]

Weitere Änderungen für die nächste Version werden hier gesammelt.

## [0.6.0] - 2026-09-08

- Added the read-only Decision Intelligence layer with persisted recommendations,
  declarative rule evaluation, decision history, and approval foundations.
- Added `get_operations_recommendations` and `get_decision_history` to MCP
  with the `agent:operations:recommend` scope.
- Added Operations Center presentation and Decision Engine documentation.

## [0.5.0] - 2026-09-08

- Added the v0.5 Operations Intelligence layer: daily operations briefing,
  expanded Security Posture, redacted Knowledge API, and provider health
  history with dedicated read-only Agent API scopes.
- Added `get_daily_operations_briefing` and `get_knowledge_context` to the
  MCP adapter and documented the API governance and v0.5 contracts.
- Added PostgreSQL persistence for sanitized knowledge entries and provider
  synchronization history; resolved incidents can contribute a summary entry.


- Added v0.4 Incident Reconstruction API/MCP read-only replay, including stored correlation chains, status history, provider origins, and alert grouping without raw payloads.
- Added historical intelligence summary, Security Briefing, and safe service dependency graph endpoints with dedicated agent scopes and MCP tools.
- Extended the operations dashboard with Security Briefing, dependency graph, and incident replay views.


- Added production observability metrics for API latency/auth/rate limits, MCP tool calls/errors/sessions, correlation activity, provider quality, and agent access.
- Added optional Prometheus/Grafana Compose observability profile with a Clawforge Overview dashboard.
- Added read-only `GET /api/v1/agents/status` and the matching `get_agent_status` MCP tool.
- Added CI validation for Rust, frontend, security scanning, Compose configuration, and Docker builds.
- Completed the application security audit for v1 readiness: protected all
  legacy intelligence/network read routes with authentication, role checks,
  and audit records, added a 256 KiB MCP request-size limit, and normalized
  framework parser failures to generic errors. Added active authorization,
  input-validation, redaction, container, frontend, and read-only MCP
  regression coverage. Compose host ports now bind to loopback by default.
- Added the controlled security-audit report and hardened Agent API incident
  identifier validation so malformed IDs return generic authenticated errors.
- Fixed PostgreSQL alert aggregation so the Operations Summary remains
  available when no alerts exist.
- Added historical operations snapshots, trend signals, grouped alert aging,
  correlation confidence, Security Posture, and matching read-only MCP tools.
- Added PostgreSQL-backed notification channels, rules, retries, and internal delivery worker.
- Added the canonical event backbone with consumer delivery, deduplication, retry/dead-letter handling, internal service authentication, and event metrics.
- Added optional event consumption for the notifier and analyzer services.
- Added read-only visualization APIs and an SVG-based frontend view for event timelines, network relationships, incident correlations, and trusted infrastructure.
- Expanded the frontend into an operations dashboard with runtime cards, Prometheus monitoring values, filtered event streaming, incident relationship details, and richer ASN/BGP/RPKI tables.
- Added provider quality and failure metadata, the read-only provider status and operations summary APIs, and matching MCP tools.
- Added an Operations Summary dashboard view, source/time incident filters, audit explorer filters, and retention documentation.

## [0.4.0] - 2026-09-08

- Added operations snapshots and bounded historical/trend views through Agent
  API v1.
- Added correlation confidence, same-source correlation, grouped alert
  deduplication, aging, and confidence metadata.
- Added Security Posture API/MCP views and dashboard presentation.
- Completed the controlled security audit, fixed empty-alert aggregation and
  malformed incident identifier error disclosure, and documented the remaining
  optional sqlx-mysql advisory.

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

[Unreleased]: https://github.com/lesecuritae/clawforge/compare/v0.6.0...HEAD
[0.6.0]: https://github.com/lesecuritae/clawforge/releases/tag/v0.6.0
[0.5.0]: https://github.com/lesecuritae/clawforge/releases/tag/v0.5.0
[0.4.0]: https://github.com/lesecuritae/clawforge/releases/tag/v0.4.0
[0.3.0]: https://github.com/lesecuritae/clawforge/releases/tag/v0.3.0
