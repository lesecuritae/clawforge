# Update and rollback

Use `scripts/update.sh` for a controlled update. It creates and validates a
custom-format PostgreSQL dump, rebuilds the API and worker images, waits for
`/ready` (including migration status), and keeps the previous image IDs for a
rollback. If readiness fails, the script restores the previous images and the
database dump before starting the stack again.

The migration guard refuses to start a binary whose migration set is older
than the database. sqlx migrations are forward-only; test upgrades on an
isolated copy before production deployment.
