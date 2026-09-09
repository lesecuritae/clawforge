# Clawforge v0.11.0 Production Hardening

This release adds the operational controls needed for a continuously running
Clawforge installation while preserving the existing read-only agent boundary.

## Execution workers

The executor registers a named worker in `execution_workers`, refreshes a
heartbeat, and records bounded leases and execution metrics. Leases expire and
are safe to reclaim after a worker disappears. The executor still requires
`CLAWFORGE_EXECUTOR_DRY_RUN=true`; no connector mutation or shell command is
enabled by this release. Queue transitions and metrics remain auditable.

## Connector ecosystem

Docker, GitHub, and Proxmox now advertise the additional read projections for
containers/images/networks/volumes, repositories/issues/actions/releases, and
platform nodes/VMs/storage. Declarative action names for restart, start/stop,
reboot, migration, workflow, and issue operations are registered disabled.
`execute` and `destructive` connector permissions remain disabled by default;
an action requires policy, role, approval, timeout, and audit before a future
release could enable it.

## Roles and metrics

The RBAC registry now includes Viewer, Operator, Approver, and Administrator
with explicit read/approve/execute/manage permissions. `GET /metrics` remains
the Prometheus endpoint; agents with `agent:metrics:read` may use the bounded
read-only `GET /api/v1/metrics` projection. It exposes action totals, duration,
worker health, connector health, policy denials, provider state, and existing
system metrics without secrets or raw payloads.

## Recovery and secrets

Worker state, leases, and metrics are included in the normal PostgreSQL backup
and restore flow. Connector credentials continue to use Docker Secret files or
external secret injection; no secret value is persisted in the new tables.
The existing backup/restore scripts must be run against a fresh database before
enabling any future connector action.

Migration `0026_platform_hardening.sql` is applied by the standard sqlx
migrator and is protected by the existing downgrade guard.
