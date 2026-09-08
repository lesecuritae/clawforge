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
