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
# Clawforge v0.9.0 Controlled Operations

- Allowlisted Action Registry and declarative action policy
- Approval-gated, fully audited execution requests
- Dry-run-only executor service with no external mutation
- Read-only Agent API and MCP status tools
- Operations Center Controlled Operations view

Migrations 0023 and 0024 are applied automatically. Productive connector
execution is intentionally unavailable in this release.
# Clawforge v1.0.0 — Operations Intelligence Platform

Clawforge v1.0.0 is the first stable release of the self-hosted Operations
Intelligence Platform. It brings infrastructure, events, incidents, risk and
trust context, decisions, controlled workflows, connectors, and LLM access
together behind audited APIs and a read-only MCP interface.

## Highlights

- Event correlation, incident management, provider intelligence, decision
  support, workflow governance, and controlled dry-run operations.
- Agent API v1, MCP integration, OpenClaw integration guidance, audit trails,
  PostgreSQL migrations, health checks, monitoring, and backup documentation.
- MCP and LLM access remain read-only. No automatic remediation or direct MCP
  database access is enabled.

## Docker Images

The production images are published at `ghcr.io/lesecuritae`:

```text
ghcr.io/lesecuritae/clawforge-api:1.0.0
ghcr.io/lesecuritae/clawforge-mcp:1.0.0
ghcr.io/lesecuritae/clawforge-frontend:1.0.0
ghcr.io/lesecuritae/clawforge-correlation:1.0.0
ghcr.io/lesecuritae/clawforge-incidents:1.0.0
ghcr.io/lesecuritae/clawforge-worker:1.0.0
ghcr.io/lesecuritae/clawforge-executor:1.0.0
```

The same images are also published with the release alias `v1.0.0`. Each image
also receives `1.0` and `latest` tags. Release builds target
`linux/amd64` and `linux/arm64`, include OCI revision metadata, provenance,
and an SBOM, and are scanned with Trivy. See [docs/deployment.md](docs/deployment.md)
for pull-based installation and upgrade instructions.

## Übersicht (Deutsch)

Clawforge v1.0.0 ist die erste stabile Version einer selbsthostbaren
Operations-Intelligence-Plattform. Sie verbindet Infrastruktur, Ereignisse,
Incidents, Risiko- und Trust-Kontext, Decisions, kontrollierte Workflows,
Connectoren und LLM-Zugriff über auditierten APIs und eine read-only
MCP-Schnittstelle.

### Highlights

- Event-Correlation, Incident Management, Provider Intelligence, Decision-
  Unterstützung, Workflow Governance und kontrollierte Dry-Run-Abläufe.
- Agent API v1, MCP/OpenClaw-Hinweise, Audit, PostgreSQL-Migrationen,
  Health Checks, Monitoring und Backup-Dokumentation.
- MCP und LLM-Zugriff bleiben read-only. Keine automatische Remediation und
  kein direkter MCP-Datenbankzugriff.

### Änderungen und Upgrade-Hinweise

Die Version hebt die dokumentierte Projektbasis und alle Workspace-Pakete auf
1.0.0 an. Bestehende Migrationen werden vor dem Readiness-Status ausgeführt.
Vor einem Upgrade von v0.x ein PostgreSQL-Backup erstellen; danach Images
ziehen, Compose neu starten und `/ready` sowie MCP-Discovery prüfen.

### Docker Images

Die Images sind unter `ghcr.io/lesecuritae` verfügbar und erhalten die Tags
`v1.0.0`, `1.0.0`, `1.0` und `latest`. Unterstützt werden `linux/amd64` und
`linux/arm64`.
Sie enthalten OCI-Revision, Provenance und SBOM und werden mit Trivy geprüft.

### LLM-Integration

OpenClaw verwendet MCP ausschließlich read-only mit begrenzten Agent-Scopes.
Kontrollierte Aktionen benötigen weiterhin Decision, Policy, menschliche
Freigabe, Queue, Worker und Audit. Details stehen in
`docs/llm-integration.de.md` und `docs/llm-integration.md`.

### Zukunftsroadmap: Operations Firewall Foundation

Clawforge v1.0 bleibt eine Operations-Intelligence-Plattform. Eine spätere
Kontrollschicht kann Agent-Fähigkeiten, Kontext, Policy, Risiko, Freigaben,
Audit und Ausführung zwischen MCP/API und Infrastruktur steuern. Die v1.0
behauptet damit nicht, eine klassische Netzwerk-Firewall zu ersetzen.

# Clawforge v0.10.0 Production Operations

## Production operations maturity

- Execution requests now expose queued, starting, running, success, failed,
  timeout, and rollback-required states with bounded retry and timeout
  metadata.
- Idempotency keys prevent duplicate execution requests. Connector permission
  records default to read-only; execute and destructive permissions remain
  disabled.
- Approval policies describe the minimum review depth for each risk level. They
  do not grant approval automatically.
- `GET /api/v1/operations/state` and MCP tools
  `get_operations_state`, `get_pending_approvals`, `get_execution_history`,
  and `get_connector_health` provide a sanitized read-only view.

The executor remains dry-run only. No shell commands, connector mutations, or
automatic remediation are enabled in this release.

# Clawforge v0.11.0 Production Hardening

- Execution worker registration, heartbeat and lease recovery metadata
- Prometheus action, duration, worker and policy-denial metrics
- Expanded safe read-only Docker, GitHub and Proxmox connector projections
- Explicit Viewer/Operator/Approver/Administrator permission registry
- Authenticated read-only Agent API metrics at `/api/v1/metrics`

Productive connector actions remain disabled. The executor requires
`CLAWFORGE_EXECUTOR_DRY_RUN=true`; no shell commands or automatic remediation
are available. Apply migration `0026_platform_hardening.sql` through the
standard startup migration path and run the documented backup/restore check.

# Clawforge v0.12.0 Incident Intelligence

- Incident Management Core adds sanitized append-only timeline records while
  preserving existing correlation and lifecycle APIs.
- Declarative alert rules, alert groups, and deduplicated correlation events
  provide a safe foundation for alert correlation.
- Docker, Proxmox, and GitHub actions are registered as disabled,
  approval-gated metadata only. The executor remains dry-run and performs no
  external operation.
- Secret provider and reference metadata supports Docker Secrets, environment
  references, Vaultwarden, SOPS, and external providers without storing values.
- MCP adds the read-only `get_incident_details` alias; no write tool or direct
  database access was added.

Apply `0027_incidents.sql` and `0028_incident_status_compatibility.sql` through the standard startup migration path. Verify
`/ready`, run the fresh migration test, and complete a backup/restore check
before production rollout.
