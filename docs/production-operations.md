# Production Operations v0.10

The production maturity layer makes controlled operation state visible while
keeping external execution disabled. Execution requests are persisted behind
PostgreSQL and can be inspected through the authenticated Agent API and the
read-only MCP adapter.

## Safety boundaries

- The executor runs with `CLAWFORGE_EXECUTOR_DRY_RUN=true` and performs no
  shell command or connector mutation.
- Connector permissions are explicit. `read` is enabled for registered
  connectors; `execute` and `destructive` are disabled by default.
- Approval policies describe the minimum approvals for each risk level. They
  do not grant approval automatically.
- Idempotency keys, bounded retries, timeout metadata, and recovery records
  make requests auditable and prevent accidental duplicate submissions.

## Read-only operations state

Agents with `agent:operations:state` can call
`GET /api/v1/operations/state`. The response contains queue counts, pending
approval counts, running requests, connector health, provider health, and the
`dry_run` execution mode. The route does not expose secrets, raw payloads, or
database credentials.

MCP exposes the same contract through `get_operations_state`,
`get_pending_approvals`, `get_execution_history`, and
`get_connector_health`. MCP has no approve, cancel, execute, or database tool.

## Operations Center

The Controlled Operations view displays registered actions, queue and approval
counts, execution history, connector health, and provider health. It is a
presentation of API data only; all state changes remain behind existing
administrator/operator policy and approval routes.

## Migration and backup

Migration `0025_production_operations.sql` adds execution metadata,
connector permissions, approval policies, recovery records, and entity
relationships. Apply it through the normal migration runner. Include the new
tables in PostgreSQL backups and verify a fresh migration plus restore before
enabling production operations. The dry-run flag must remain enabled until a
separate reviewed release activates a specific connector action.

## Dependency validation

`npm audit` reports no frontend vulnerabilities. `cargo audit` reports the
known transitive `RUSTSEC-2023-0071` advisory for `rsa`; the dependency is
pulled by the existing optional PostgreSQL authentication stack and no fixed
upstream version is available. It is not used for connector execution or
secret storage and remains tracked for the next dependency review.
