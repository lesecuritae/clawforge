# Clawforge v1.0.0 final release

## What is Clawforge?

Clawforge is a self-hosted Operations Intelligence platform. It collects
structured infrastructure and security events, correlates them, creates
traceable incidents, evaluates risk and trust, and presents a shared operating
context to people and read-only LLM agents.

It is not an autonomous AI administrator. Clawforge explains what happened,
why it matters, and what should be checked. Controlled operations use an
allowlist, policy checks, explicit approvals, an execution queue, and audit
records. The v1.0 executor remains dry-run by default.

## Why it exists

Infrastructure information is split across containers, servers, providers,
repositories, monitoring systems and security feeds. Clawforge provides one
redacted, auditable layer for understanding those signals without giving an
agent hidden access or unrestricted command execution.

## Architecture

```text
Connectors / Providers -> Event Backbone -> Correlation -> Incidents / Alerts
                                      -> Risk / Trust / Policy
                                      -> Decisions -> Workflows -> Controlled Operations
                                      -> Agent API v1 -> MCP -> LLM agents
```

PostgreSQL is the source of truth. Rust services use sqlx migrations; the
frontend is API-only. MCP never connects directly to PostgreSQL or the event
backbone.

## Stable v1.0 capabilities

- Event, alert, correlation, incident and timeline processing
- Threat, ASN, BGP, RPKI, risk and trusted-infrastructure context
- Explainable decisions, workflows, approvals and audit history
- Read-only Agent API v1 and scoped MCP integration for OpenClaw
- Docker, GitHub and Proxmox connector foundations
- PostgreSQL persistence, backup/restore workflows, health checks and metrics
- React/TypeScript Operations Dashboard

## Security model

Least privilege, explicit scopes, append-only audit records, human approval for
critical actions, secret separation, bounded responses, and no single-feed
blocking are release requirements. Secret values never enter the repository,
MCP responses, logs, or PostgreSQL metadata tables.

## Installation and operation

Use [deployment.md](deployment.md) for Compose installation, published GHCR
images, migrations, health checks, upgrades, and rollback. Use
[backup.md](backup.md) and [recovery.md](recovery.md) before production
updates. The LLM boundary is described in [llm-integration.md](llm-integration.md).

## Roadmap after v1.0

Future releases may add reviewed connector execution, richer knowledge and
trend intelligence, additional integrations, and signed image attestations.
They must preserve the read-only MCP boundary, approval requirements, audit
coverage, and secret isolation.

### Operations Firewall foundation

The v1.0 product remains an Operations Intelligence Platform. A later control
layer may govern AI agents, automation, infrastructure actions and operational
decisions without replacing a classical network firewall:

```text
LLM Agent
   |
 MCP/API
   |
Clawforge Control Firewall
   |-- Context
   |-- Policy
   |-- Risk
   |-- Approval
   |-- Audit
   `-- Execution Control
   |
Infrastructure
```

Possible capabilities include agent capability control, context filtering,
risk-based approvals, sandbox execution, rollback, configuration guardrails,
drift detection and complete decision auditing. This is a post-v1.0 direction;
the v1.0 release does not claim to be an Operations Firewall.
