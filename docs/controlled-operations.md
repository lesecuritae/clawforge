# Controlled Operations v0.9

Clawforge v0.9 introduces a governance layer for registered operations. The
action registry is an allowlist backed by PostgreSQL. Actions are disabled by
default and the executor refuses to start unless `CLAWFORGE_EXECUTOR_DRY_RUN`
is `true`.

Execution requests are created only by an authenticated Operator or
Administrator, are checked against the action policy, and are audited on every
state transition. Risky actions enter `waiting_approval`. Their required count
and expiry are snapshotted from the risk policy, and each approval is bound to
an immutable SHA-256 request context. The requester cannot approve their own
request, every approver identity counts once, and high/critical requests remain
blocked until two distinct active approvers have approved within the window.
The same transition and approval-count rules are enforced by PostgreSQL
triggers, so a direct status update cannot bypass them. The executor only
records a bounded dry-run result and never invokes a shell, container API,
GitHub API, or other external system.

Creation, approval and every executor state transition write their audit row
and durable audit-outbox entry in the same database transaction. If audit
insertion fails, the state change is rolled back. Publishing to the canonical
event backbone happens from the retryable outbox with an idempotent dedupe key.

## Read-only API and MCP

Agents can read `/api/v1/actions` with `agent:action:read` and
`/api/v1/executions` with `agent:execution:read`. MCP exposes
`list_actions`, `get_execution_status`, and `list_pending_executions`. No MCP
tool can create, approve, cancel, or execute a request.

Migration 0023 adds the action registry and explicit connector capability
modes (`read`/`execute`). Migration 0024 stores execution requests and bounded
result/error summaries. Migration 0029 adds immutable execution approval
records, requester separation, expiry, context hashes, and the database state
machine. Migration 0030 adds the durable audit outbox and makes audit rows
append-only. Credentials and connector configuration never enter these tables.
