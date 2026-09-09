# Changelog

## [Unreleased]

Weitere Änderungen für die nächste Version werden hier gesammelt.

## [1.0.0] - 2026-09-09

- Marked the first stable Clawforge release as a self-hosted Operations
  Intelligence Platform for people and read-only LLM agents.
- Consolidated the documented Event, Correlation, Incident, Risk, Trust,
  Decision, Workflow, Connector, Agent API, and MCP architecture.
- Added the final LLM/MCP integration, deployment, security, and release
  documentation for installation and long-term operation.
- Added a GHCR release pipeline for OCI-labelled, multi-architecture images
  with SBOM and Trivy validation.
- Preserved read-only MCP access, approval-gated dry-run execution, and
  secret separation as release boundaries.
- Added equivalent German and English release documentation for architecture,
  LLM/MCP integration, deployment, security, and final-release guidance.

## [0.12.0] - 2026-09-09

- Added additive incident intelligence storage with incident titles, sources,
  sanitized append-only timelines, declarative alert grouping, and correlation
  event deduplication.
- Added disabled, approval-gated Docker, Proxmox, and GitHub action metadata;
  the executor remains dry-run only and no external mutation is enabled.
- Added secret provider/reference metadata for Docker Secrets, environment
  references, Vaultwarden, SOPS, and external providers without persisting
  secret values.
- Added the read-only MCP alias `get_incident_details` and documented the
  v0.12 upgrade, security boundaries, and operational checks.

## [0.11.0] - 2026-09-09

- Added production execution worker registration, heartbeats, bounded leases,
  recovery metadata, and execution metrics. The executor remains dry-run only.
- Extended Docker, GitHub, and Proxmox connector metadata with safe read
  capabilities and disabled action registrations for future policy-gated work.
- Added explicit Viewer, Operator, Approver, and Administrator permission
  mappings plus the authenticated read-only `/api/v1/metrics` endpoint.
- Added Prometheus action, duration, worker-health, and policy-denial metrics;
  migration `0026_platform_hardening.sql`; and production hardening guidance.

## [0.10.0] - 2026-09-09

- Added the production operations maturity layer with execution queue state,
  idempotency keys, retry/timeout metadata, safe dry-run status transitions,
  and recovery records. Productive destructive execution remains disabled.
- Added connector permission metadata, approval policies, and entity
  relationship storage with conservative defaults (`read` only enabled).
- Added the read-only Agent API operations state resource and four MCP tools
  for operations state, pending approvals, execution history, and connector
  health. All responses stay redacted and audit-compatible.
- Extended the Operations Center with queue, approval, connector-health, and
  provider-health visibility.

## [0.9.0] - 2026-09-09

- Added the controlled operations layer with an allowlisted Action Registry,
  explicit connector read/execute capability metadata, and audited execution
  request state transitions.
- Added policy checks, administrative approval/cancel endpoints, Agent API v1
  read-only action/execution resources, and three read-only MCP tools.
- Added the non-invasive `clawforge-executor` service. It accepts only
  `CLAWFORGE_EXECUTOR_DRY_RUN=true` and records no-op results; no shell or
  external operation is executed.
- Added the Controlled Operations dashboard and migration/backup documentation.

## [0.8.0] - 2026-09-09

- Added the read-only Connector Framework with Docker, GitHub, and Proxmox
  foundation registrations, health records, capabilities, and audit logging.
- Added Agent API v1 connector resources and three sanitized MCP connector
  tools under `agent:connector:read`.
- Added the Operations Center Connectors view and connector security
  documentation. No external mutation or connector action is available.

## [0.7.0] - 2026-09-08

- Added controlled Workflow Governance with declarative workflow definitions,
  steps, prepared runs, approvals, and immutable workflow audit records.
- Added read-only Agent API workflow resources and three MCP workflow tools.
- Added Operations Center workflow overview and documentation for approval
  boundaries. No workflow step or external system action is executed.

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

[Unreleased]: https://github.com/lesecuritae/clawforge/compare/v0.8.0...HEAD
[0.8.0]: https://github.com/lesecuritae/clawforge/releases/tag/v0.8.0
[0.7.0]: https://github.com/lesecuritae/clawforge/releases/tag/v0.7.0
[0.6.0]: https://github.com/lesecuritae/clawforge/releases/tag/v0.6.0
[0.5.0]: https://github.com/lesecuritae/clawforge/releases/tag/v0.5.0
[0.4.0]: https://github.com/lesecuritae/clawforge/releases/tag/v0.4.0
[0.3.0]: https://github.com/lesecuritae/clawforge/releases/tag/v0.3.0
