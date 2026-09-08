# Data retention and maintenance

Clawforge keeps PostgreSQL as the source of truth. Retention is applied by
bounded worker jobs and database policies; it must never remove audit evidence
without an explicitly documented administrative process.

## Operational data

- Indicators are expired from the active set at their `expires_at` time. The
  worker performs this cleanup during its regular maintenance cycle.
- Events and correlation relationships should be archived to the configured
  backup/archive store before their operational retention window is reached.
- Incident records and their timeline remain available while an incident is
  open or under investigation. Closed incident retention must be agreed with
  the operator and validated against the backup policy.
- Audit events are append-only operational evidence. Retention and archival
  must preserve timestamps, actor, action, source, severity, and reason.

## Backup and restore

Run the scheduled PostgreSQL backup before any retention change. Validate a
custom-format dump with `scripts/backup.sh`, and use `scripts/restore.sh` for a
restore test on an isolated database. A fresh database must apply all sqlx
migrations before the API is considered ready. See [backup.md](backup.md) and
[update.md](update.md) for the operational procedures.

No retention job performs a block, policy, trust, or provider action.
