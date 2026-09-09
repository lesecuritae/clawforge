# Clawforge v0.8.0 Connector Framework

## Read-only infrastructure connectors

- Connector registry with metadata, health, capabilities, and audit events.
- Docker connector capabilities for container status, health, image versions,
  and restart counts.
- GitHub repository and Proxmox health connector foundations.
- Agent API v1 resources and MCP tools `list_connectors`,
  `get_connector_status`, and `get_connector_capabilities`.
- Operations Center Connectors view.

Connector credentials remain outside the repository and are injected through
secret files. No restart, write, policy, workflow, or external mutation is
implemented.

# Clawforge v0.7.0 Workflow Governance

## Controlled workflow layer

- Declarative workflows and allowlisted steps (`notification`, `analysis`,
  `approval`, `external_check`, `manual`).
- Prepared workflow runs linked to Decision Engine recommendations.
- Approval state, comments, reasons, and workflow audit history.
- Agent API read-only workflow resources and MCP tools:
  `list_workflows`, `get_workflow_status`, `get_workflow_history`.
- Operations Center workflow overview.

Approvals only record governance state. No workflow executor, shell execution,
automatic provider action, policy change, or external system mutation is part
of v0.7.0.

# Clawforge v0.6.0 Decision Intelligence

## Decision Intelligence

- Persisted explainable decisions and read-only Operations Recommendations API.
- Declarative rules and rule execution history without script execution.
- Approval foundation for future workflows; no action is executed in v0.6.
- MCP tools `get_operations_recommendations` and `get_decision_history`.
- Operations Center view for current recommendations and decision history.

The Decision Engine is strictly advisory. It does not change Risk, Trust,
Policy, providers, or system configuration.

# Clawforge v0.5.0

## Operations Intelligence expansion

- Daily Operations Briefing through Agent API v1 with existing incidents,
  alerts, events, provider health, trends, and recommended checks.
- Expanded Security Posture response with incident, alert, provider, policy,
  trust, and trend context.
- Redacted Knowledge Context API and MCP tool for resolved-incident summaries,
  lessons learned, and recurring patterns.
- Provider synchronization and quality history persisted in PostgreSQL and
  exposed read-only through Agent API v1.
- API governance, scopes, OpenAPI contracts, and MCP documentation updated.

The v0.5 release remains read-only for agents and MCP. No new provider feed,
automatic remediation, or direct MCP database access was added.

# Clawforge v0.4.0

## Production operations update

- Expanded API and MCP Prometheus metrics for response latency, authentication failures, tool calls, active sessions, correlations, provider quality, and agent access.
- Added optional Prometheus/Grafana deployment and the Clawforge Overview dashboard.
- Added the read-only agent health endpoint and MCP adapter tool.
- Added GitHub CI checks for tests, linting, frontend builds, security scans, Compose validation, and Docker builds.

Historical Operations Intelligence release with controlled security-audit
hardening.

## Application security audit update

- Protected the unversioned legacy intelligence and network read routes with
  bearer authentication, read-role authorization, and audit events.
- Added a 256 KiB request-body limit to the Streamable HTTP MCP adapter while
  retaining the existing response-size and redaction guards.
- Normalized malformed path and query extractor failures to generic `400`
  responses so parser details and echoed input are not disclosed.
- Changed Compose API and frontend host-port defaults to loopback-only binds;
  external exposure now requires explicit host bind configuration.
- Re-ran authorization, scope-escalation, malformed-input, rate-limit,
  read-only MCP, secret-scan, frontend, container, and Compose checks.

## Highlights

- Incident replay reconstructs stored event, correlation, indicator, provider, alert, and status history with existing redaction.
- Historical operations summaries expose bounded trends and anomalies for hour/day/week intervals.
- Security Briefing and System Graph are available through Agent API v1 and four new read-only MCP tools.
- Dashboard adds replay, briefing, and dependency graph views; no remediation or write access was added.

- Operations snapshots, history filtering, trend direction, reason, and
  confidence through Agent API v1.
- Correlation confidence and same-source fallback correlation.
- Alert grouping, deduplication, aging, and event counts.
- Security Posture API, MCP tool, and frontend view.
- Security audit report with fixes for empty alert aggregation and malformed
  incident identifier error disclosure.

## Validation

- Rust format, workspace tests, Clippy, frontend tests/build, OpenAPI parsing.
- Docker Compose configuration, complete service builds, migration/readiness
  checks, health checks, PostgreSQL persistence, and backup/restore.
- Agent API and MCP authentication, authorization, rate-limit, redaction, and
  read-only checks.

The `cargo audit` result contains the documented medium advisory for the
optional, unused `sqlx-mysql` dependency; Clawforge builds PostgreSQL only and
there is no upstream fixed version yet.

The previous v0.3.0 release notes follow.

---

# Clawforge v0.3.0

Production OpenClaw live-integration validation for the standalone Rust
security-intelligence platform.

## OpenClaw integration

- Isolated `clawforge-mcp` Streamable HTTP adapter remains read-only and uses
  Agent API v1 as its only data source.
- MCP discovery exposes all 14 documented tools.
- Operations Agent access uses a separate, scoped Agent API token injected as
  a secret; no token value is stored in the repository.
- Live reads of operations summary, agent context, and incidents were
  verified, including redacted Agent API audit records.
- A controlled three-event correlation produced one critical incident without
  duplicate incident records. Provider-failure validation remains dependent
  on enabling a provider feed; feeds stay disabled by default.

## Release validation

The release checklist covers Compose configuration, complete service builds,
fresh migrations, backup/restore, MCP discovery, OpenClaw read-only calls,
health/readiness checks, and secret scans. The full command results are kept
in the release work log and must be rerun before deployment.

The previous v0.1.0 foundation is retained below for historical reference.

## Included

- Axum API and Tokio worker runtime with PostgreSQL/sqlx migrations.
- Threat, ASN, BGP, RPKI, trusted infrastructure, risk, incident, audit, and metrics APIs.
- React/TypeScript API-only console with session expiry handling, pagination, filters, CSP, and hardened Nginx serving.
- Docker Compose services for API, worker, PostgreSQL, frontend, scheduled backups, and optional Redis.
- Secret-file configuration, non-root application containers, read-only filesystems, capability dropping, and readiness checks.
- Backup/restore and update/rollback workflows.
- Role-aware global and endpoint-specific API limits with 429 responses, retry headers, and audit events.

## Validation

- `cargo fmt --all -- --check`
- `cargo test --workspace`
- `cargo clippy --workspace --all-targets -- -D warnings`
- API rate-limit tests for limits, roles, 429 responses, retry headers, and audit events
- PostgreSQL migration/restart integration test
- Backup/restore integrity test
- Live Feodo and Spamhaus DROP/EDROP/ASN feed checks
- Fresh Compose deployment, migration readiness, admin bootstrap, login, frontend access, and worker/backup service checks
- Update path with backup and rollback path
- Frontend `npm test`, production build, dependency audit, Docker build, Compose smoke test, and security-header check

Authenticated providers remain disabled unless their Docker Secrets are explicitly supplied. No feed directly performs a block action.
