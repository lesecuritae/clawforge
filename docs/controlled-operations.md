# Controlled Operations v0.9

Clawforge v0.9 introduces a governance layer for registered operations. The
action registry is an allowlist backed by PostgreSQL. Actions are disabled by
default and the executor refuses to start unless `CLAWFORGE_EXECUTOR_DRY_RUN`
is `true`.

Execution requests are created only by an authenticated Operator or
Administrator, are checked against the action policy, and are audited on every
state transition. Risky actions enter `waiting_approval`; approval and cancel
remain administrative operations. The executor only records a bounded dry-run
result and never invokes a shell, container API, GitHub API, or other external
system.

## Read-only API and MCP

Agents can read `/api/v1/actions` with `agent:action:read` and
`/api/v1/executions` with `agent:execution:read`. MCP exposes
`list_actions`, `get_execution_status`, and `list_pending_executions`. No MCP
tool can create, approve, cancel, or execute a request.

Migration 0023 adds the action registry and explicit connector capability
modes (`read`/`execute`). Migration 0024 stores execution requests and bounded
result/error summaries. Credentials and connector configuration never enter
these tables.
