# Operations

The API and worker run without root privileges, drop all Linux capabilities,
use `no-new-privileges`, and use read-only root filesystems with a small `/tmp`.
PostgreSQL, Redis, and the backup job are isolated on an internal Compose
network; only the API is attached to the frontend network.

Secrets are mounted as Docker secrets. Environment variables may point to a
secret file, but credentials are not written to provider status, indicators,
audit events, metrics, or logs. Redis is optional and is used only for the
scheduler lock; PostgreSQL stores all authoritative state.

Before maintenance, take a backup, stop feed jobs if necessary, apply the
update workflow, wait for readiness, and inspect the migration version. Never
delete the PostgreSQL or backup volumes during a normal update.
