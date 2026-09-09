# LLM and MCP integration

Clawforge is an Operations Intelligence layer for people and agents. An LLM
is not given direct infrastructure access, database credentials, raw feeds, or
policy authority. It receives a bounded context assembled by Clawforge and
turns that context into an explanation or recommendation.

## Read-only context flow

```text
User question
    |
    v
OpenClaw / another LLM agent
    |
    v
Clawforge MCP (read-only, scoped)
    |
    v
Agent API v1 / Context API
    |
    +--> Events, Incidents, Risk, Trust, Provider health
    |
    v
Redacted explanation context
```

For “What is happening on my server?”, an agent can combine
`get_operations_summary`, `get_agent_context`, `get_decisions`, and incident
read tools. For “Why is this container slow?”, it can inspect the operations
summary, relevant events, incident timeline, connector health, and provider
status. Clawforge returns stored, evaluated context; it does not ask the LLM
to calculate security scores from raw data.

The connector path is generic:

```text
LLM -> MCP -> Operations Layer -> Connector Framework -> infrastructure source
```

Connectors may represent container platforms, infrastructure systems,
virtualization, repositories, cloud services, monitoring, or external data
sources. Docker, GitHub, and Proxmox are examples rather than product
boundaries. A connector contributes normalized state, health, and capabilities;
it does not expose unnecessary raw data.

## Controlled operations

A request such as “restart the container” follows the controlled path:

```text
LLM request
  -> Decision / recommendation
  -> action allowlist
  -> policy check
  -> human approval
  -> execution queue
  -> worker
  -> audit event
```

The v1.0 release keeps connector execution disabled and the executor in
`CLAWFORGE_EXECUTOR_DRY_RUN=true`. MCP has no action, approval, policy, or
cancellation tool. No prompt can bypass a policy or grant trust.

## Authentication and scopes

MCP authentication and the upstream Agent API token are separate secrets.
Tokens are injected through Docker Secret files or an external secret
reference. A minimal read-only profile should contain only the scopes needed by
an agent, such as:

- `agent:operations:read`
- `agent:context:read`
- `agent:decision:read`
- `agent:incident:read`
- `agent:provider:read`
- `agent:security:read`

Each call is bounded by timeout and response-size limits, checked against the
scope allowlist, redacted, and represented in the audit trail without token
values. See [agent-api.md](agent-api.md), [mcp-server.md](mcp-server.md), and
[openclaw-integration.md](openclaw-integration.md) for the contract.

## Data boundary

The optional analyzer receives only sanitized incident context. Raw feed
payloads, credentials, API keys, database connection strings, and internal
secret values are excluded. LLM output is advisory and cannot change risk,
trust, policy, provider state, permissions, incident status, or workflow state.
