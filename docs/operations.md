# Operations

The API and worker run without root privileges, drop all Linux capabilities,
use `no-new-privileges`, and use read-only root filesystems with a small `/tmp`.
PostgreSQL, Redis, and the backup job are isolated on an internal Compose
network; only the API is attached to the frontend network.

Secrets are mounted as Docker secrets. `./scripts/validate-secrets.sh` rejects
missing files, known placeholders, weak or duplicated service tokens, symlinks,
wrong ownership, and group/world-readable files before deployment. A configured
but unreadable or empty `_FILE` secret fails closed instead of falling back to
an environment value. Credentials are not written to provider status,
indicators, audit events, metrics, or logs. Redis is optional and is used only
for the scheduler lock; PostgreSQL stores all authoritative state.

The administrator bootstrap secret is mounted only through
`compose.bootstrap.yml` and must be removed after bootstrap. MCP is opt-in via
the `agent` profile after an issued read-only Agent API token has replaced the
initializer value.

Analyzer, event-backbone, notifier, and operations-producer tokens are
distinct identities. Event consumers are derived server-side from the token,
and acknowledgements are restricted to delivery ownership. Notification
egress is disabled until exact DNS hosts are configured; HTTPS destinations,
DNS results, redirects, SMTP configuration, and fixed per-channel secret IDs
are validated before delivery.

Before maintenance, take a backup, stop feed jobs if necessary, apply the
update workflow, wait for readiness, and inspect the migration version. Never
delete the PostgreSQL or backup volumes during a normal update.
