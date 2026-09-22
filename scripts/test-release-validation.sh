#!/usr/bin/env bash
set -Eeuo pipefail

validation_secret_dir="$(mktemp -d)"
project="clawforge-release-validation-$$"
cleanup() {
  docker compose -p "$project" down -v --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$validation_secret_dir"
}
trap cleanup EXIT INT TERM

./scripts/init-secrets.sh "$validation_secret_dir" >/dev/null
export CLAWFORGE_POSTGRES_SECRET_FILE="$validation_secret_dir/postgres_password"
export CLAWFORGE_DATABASE_URL_SECRET_FILE="$validation_secret_dir/database_url"
for role in api worker correlation incidents executor; do
  password_var="CLAWFORGE_DATABASE_$(printf '%s' "$role" | tr '[:lower:]' '[:upper:]')_PASSWORD_SECRET_FILE"
  url_var="CLAWFORGE_DATABASE_$(printf '%s' "$role" | tr '[:lower:]' '[:upper:]')_URL_SECRET_FILE"
  export "$password_var=$validation_secret_dir/database_${role}_password"
  export "$url_var=$validation_secret_dir/database_${role}_url"
done
export CLAWFORGE_DATABASE_BACKUP_PASSWORD_SECRET_FILE="$validation_secret_dir/database_backup_password"
export CLAWFORGE_ADMIN_BOOTSTRAP_SECRET_FILE="$validation_secret_dir/admin_bootstrap_token"
export CLAWFORGE_ANALYZER_SECRET_FILE="$validation_secret_dir/analyzer_token"
export CLAWFORGE_ANALYZER_API_KEY_SECRET_FILE="$validation_secret_dir/analyzer_api_key"
export CLAWFORGE_NOTIFIER_SECRET_FILE="$validation_secret_dir/notifier_token"
export CLAWFORGE_NOTIFICATION_WEBHOOK_SECRET_FILE="$validation_secret_dir/notifier_webhook_auth"
export CLAWFORGE_NOTIFICATION_MATRIX_SECRET_FILE="$validation_secret_dir/notifier_matrix_auth"
export CLAWFORGE_NOTIFICATION_SMTP_SECRET_FILE="$validation_secret_dir/notifier_smtp_password"
export CLAWFORGE_EVENTS_SECRET_FILE="$validation_secret_dir/events_token"
export CLAWFORGE_OPERATIONS_SECRET_FILE="$validation_secret_dir/operations_token"
export CLAWFORGE_MCP_AGENT_TOKEN_FILE="$validation_secret_dir/mcp_agent_api_token"
export CLAWFORGE_MCP_AUTH_TOKEN_FILE="$validation_secret_dir/mcp_auth_token"
export CLAWFORGE_GITHUB_TOKEN_FILE="$validation_secret_dir/github_token"
export CLAWFORGE_PROXMOX_TOKEN_FILE="$validation_secret_dir/proxmox_token"
export CLAWFORGE_THREATFOX_SECRET_FILE="$validation_secret_dir/threatfox_auth_key"
export CLAWFORGE_URLHAUS_SECRET_FILE="$validation_secret_dir/urlhaus_auth_key"
export CLAWFORGE_MALWAREBAZAAR_SECRET_FILE="$validation_secret_dir/malwarebazaar_auth_key"

# Full release gate. Live provider requests remain bounded and authenticated
# feeds are skipped unless their keys are injected into this process.
export CLAWFORGE_ENABLE_FEEDS=true

cargo fmt --all -- --check
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings

./scripts/test-provider-smoke.sh
./scripts/test-postgres.sh
./scripts/test-backup-restore.sh

CLAWFORGE_API_PORT=18080 docker compose -p "$project" config --quiet
./scripts/validate-secrets.sh
./scripts/test-secret-hardening.sh
CLAWFORGE_API_PORT=18080 docker compose -p "$project" up -d --build
until curl --fail --silent http://127.0.0.1:18080/ready >/dev/null; do sleep 2; done
curl --fail --silent http://127.0.0.1:18080/health >/dev/null
curl --fail --silent http://127.0.0.1:18080/version >/dev/null
for endpoint in \
  /intelligence/providers \
  /intelligence/status \
  /intelligence/indicators \
  /network/asn \
  /network/bgp \
  /network/rpki \
  /network/trust; do
  status="$(curl --silent --output /dev/null --write-out '%{http_code}' "http://127.0.0.1:18080${endpoint}")"
  [ "$status" = 401 ] || { echo "expected protected legacy endpoint ${endpoint} to return 401, got ${status}" >&2; exit 1; }
done
curl --fail --silent http://127.0.0.1:18080/metrics >/dev/null
backup_container="$(docker compose -p "$project" ps -q clawforge-backup)"
until [ -n "$backup_container" ] && docker exec "$backup_container" sh -ec "test -n \"\$(find /backups -maxdepth 1 -name 'clawforge-*.dump' -print -quit)\""; do
  sleep 2
done
echo "release validation: ok"
