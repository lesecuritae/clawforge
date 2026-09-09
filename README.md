# Clawforge

**Self-hosted Operations Intelligence Platform**

Clawforge connects infrastructure, events, security information, operational
telemetry, and controlled automation in one auditable operations layer. People
and LLM agents receive the same redacted context through the versioned Agent
API and the read-only MCP server.

Clawforge is not an autonomous AI administrator. It collects and evaluates
information, explains relationships, and exposes controlled interfaces for
people and agents. External actions are allowlisted, policy checked, approval
gated, audited, and dry-run by default in v1.0.0.

[English](README.md) · [Deutsch](README.de.md)

![Clawforge Operations Intelligence](assets/branding/rebranding-announcement.png)

## Why Clawforge?

Modern environments combine containers, servers, cloud services, repositories,
monitoring, security feeds, and automation. Information is produced in many
places, while the relationships between signals are difficult to see.
Clawforge provides one Operations Intelligence layer: it collects events,
correlates them, preserves traceable incidents, and combines risk, trust,
provider health, and recommendations.

## Architecture

```text
Infrastructure
      |
Connector Layer
      |
Provider Intelligence
      |
Event Backbone
      |
Correlation Engine
      |
Incident Intelligence
      |
Risk / Trust / Policy Engine
      |
Decision Intelligence
      |
Workflow Governance
      |
Controlled Operations
      |
Agent API v1
      |
MCP Server
      |
LLM Agent
```

- **Connectors** read safe projections from Docker, GitHub, and Proxmox.
- **Provider Intelligence** normalizes threat, ASN, BGP, and RPKI data.
- **Event Backbone** persists structured events for correlation, incidents,
  alerts, and audit consumers.
- **Correlation and Incident Intelligence** preserve relationships and an
  auditable incident lifecycle.
- **Risk, Trust, and Policy** evaluate signals separately. A single feed, ASN,
  RPKI status, or connector cannot block by itself.
- **Decision and Workflow Governance** produce explainable recommendations and
  manage approvals.
- **Controlled Operations** only knows registered actions. The v1.0 executor
  is dry-run and performs no external mutation.
- **Agent API and MCP** expose bounded, redacted, read-only context to OpenClaw
  and other agents.

The detailed architecture is in [docs/architecture.md](docs/architecture.md)
(and [Deutsch](docs/architecture.de.md)).

## Feature matrix

| Area | Capabilities |
| --- | --- |
| Security Intelligence | Events, correlation, incidents, alerts, risk and trust evaluation |
| Operations Intelligence | Context API, Operations Summary, briefings, decisions, history |
| Automation Governance | Workflows, actions, approvals, execution queue, audit |
| Integration | MCP, OpenAPI, Docker, GitHub, Proxmox, OpenClaw |
| Platform | Rust, PostgreSQL/sqlx, migrations, backup/restore, Prometheus, dashboard |

Clawforge uses an extensible Connector Framework rather than a technology-
specific administrator. Connectors provide normalized state, health, and
capabilities for container platforms, infrastructure systems, virtualization,
repositories, cloud services, monitoring, and external data sources. Docker,
GitHub, and Proxmox are the initial examples.

## LLM and MCP integration

LLMs do not receive direct infrastructure or database access. MCP calls only the
Agent API v1 and returns bounded, redacted responses. Scopes, timeouts,
response limits, and audit records apply to every call.

```text
LLM -> MCP -> Agent Context API -> Events / Incidents / Risk / Provider health
     -> explanation or recommendation
```

A controlled operation follows this path:

```text
LLM -> Decision -> Policy -> Approval -> Execution Queue -> Worker -> Audit
```

MCP remains read-only: it has no direct database access, hidden actions, or
write tools. See [docs/llm-integration.md](docs/llm-integration.md) and
[docs/llm-integration.de.md](docs/llm-integration.de.md).

## Docker installation

Requirements: Docker Engine and the Docker Compose plugin.

```bash
git clone https://github.com/lesecuritae/clawforge.git
cd clawforge
cp .env.example .env
# create private secret files from secrets/*.example
docker compose pull
docker compose up -d
curl http://127.0.0.1:8080/ready
```

Use `docker compose up -d --build` for a local build. Published images are
available from `ghcr.io/lesecuritae/clawforge-<service>:1.0.0` for API, MCP,
frontend, correlation, incidents, worker, and executor. See
[docs/deployment.md](docs/deployment.md) and
[docs/deployment.de.md](docs/deployment.de.md) for upgrades, backups, and
health checks.

## Security boundaries

- Least privilege through roles and explicit agent scopes.
- Append-only audit records for access, state changes, approvals, and
  executions.
- No automatic blocking or remediation from one signal or from an LLM.
- Human approval for critical operations.
- Secrets are injected with Docker Secrets or external references and never
  returned by API, MCP, logs, or frontend projections.
- Non-root containers, health checks, migration checks, and backup workflows.

See [docs/security.md](docs/security.md),
[docs/security.de.md](docs/security.de.md), and the
[security audit](docs/security-audit.md).

## Documentation

- [Architecture](docs/architecture.md) · [Deutsch](docs/architecture.de.md)
- [LLM/MCP integration](docs/llm-integration.md) · [Deutsch](docs/llm-integration.de.md)
- [Deployment and updates](docs/deployment.md) · [Deutsch](docs/deployment.de.md)
- [Security model](docs/security.md) · [Deutsch](docs/security.de.md)
- [Agent API v1](docs/agent-api.md)
- [MCP server](docs/mcp-server.md)
- [Providers](docs/providers.md)
- [Connectors](docs/connectors.md)
- [Backup and recovery](docs/backup.md)
- [Final release](docs/final-release.md) · [Deutsch](docs/final-release.de.md)

## Validation

```bash
cargo fmt --all -- --check
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
npm --prefix frontend test
npm --prefix frontend run build
docker compose config
docker compose build
```

## License

Apache License 2.0. Clawforge is an independent Rust project and contains no
KorbKlar, supermarket, or OpenClaw runtime code.
