# Clawforge v0.1.0

Release candidate for the standalone Rust security-intelligence platform.

## Included

- Axum API and Tokio worker runtime with PostgreSQL/sqlx migrations.
- Threat, ASN, BGP, RPKI, trusted infrastructure, risk, incident, audit, and metrics APIs.
- React/TypeScript API-only console with session expiry handling, pagination, filters, CSP, and hardened Nginx serving.
- Docker Compose services for API, worker, PostgreSQL, frontend, scheduled backups, and optional Redis.
- Secret-file configuration, non-root application containers, read-only filesystems, capability dropping, and readiness checks.
- Backup/restore and update/rollback workflows.

## Validation

- `cargo fmt --all -- --check`
- `cargo test --workspace`
- `cargo clippy --workspace --all-targets -- -D warnings`
- PostgreSQL migration/restart integration test
- Backup/restore integrity test
- Live Feodo and Spamhaus DROP/EDROP/ASN feed checks
- Fresh Compose deployment, migration readiness, admin bootstrap, login, frontend access, and worker/backup service checks
- Update path with backup and rollback path
- Frontend `npm test`, production build, dependency audit, Docker build, Compose smoke test, and security-header check

Authenticated providers remain disabled unless their Docker Secrets are explicitly supplied. No feed directly performs a block action.
