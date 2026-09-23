#!/usr/bin/env bash
set -Eeuo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
test_dir="$(mktemp -d)"
cleanup() { rm -rf "$test_dir"; }
trap cleanup EXIT INT TERM

"$repo_dir/scripts/init-secrets.sh" "$test_dir/secrets" >/dev/null

export CLAWFORGE_POSTGRES_SECRET_FILE="$test_dir/secrets/postgres_password"
export CLAWFORGE_DATABASE_URL_SECRET_FILE="$test_dir/secrets/database_url"
for role in api worker correlation security_engine incidents executor; do
  password_var="CLAWFORGE_DATABASE_$(printf '%s' "$role" | tr '[:lower:]' '[:upper:]')_PASSWORD_SECRET_FILE"
  url_var="CLAWFORGE_DATABASE_$(printf '%s' "$role" | tr '[:lower:]' '[:upper:]')_URL_SECRET_FILE"
  export "$password_var=$test_dir/secrets/database_${role}_password"
  export "$url_var=$test_dir/secrets/database_${role}_url"
done
export CLAWFORGE_DATABASE_BACKUP_PASSWORD_SECRET_FILE="$test_dir/secrets/database_backup_password"
export CLAWFORGE_ADMIN_BOOTSTRAP_SECRET_FILE="$test_dir/secrets/admin_bootstrap_token"
export CLAWFORGE_ANALYZER_SECRET_FILE="$test_dir/secrets/analyzer_token"
export CLAWFORGE_ANALYZER_API_KEY_SECRET_FILE="$test_dir/secrets/analyzer_api_key"
export CLAWFORGE_NOTIFIER_SECRET_FILE="$test_dir/secrets/notifier_token"
export CLAWFORGE_NOTIFICATION_WEBHOOK_SECRET_FILE="$test_dir/secrets/notifier_webhook_auth"
export CLAWFORGE_NOTIFICATION_MATRIX_SECRET_FILE="$test_dir/secrets/notifier_matrix_auth"
export CLAWFORGE_NOTIFICATION_SMTP_SECRET_FILE="$test_dir/secrets/notifier_smtp_password"
export CLAWFORGE_EVENTS_SECRET_FILE="$test_dir/secrets/events_token"
export CLAWFORGE_OPERATIONS_SECRET_FILE="$test_dir/secrets/operations_token"
export CLAWFORGE_MCP_AGENT_TOKEN_FILE="$test_dir/secrets/mcp_agent_api_token"
export CLAWFORGE_MCP_AUTH_TOKEN_FILE="$test_dir/secrets/mcp_auth_token"
export CLAWFORGE_ANALYZER_IP_HMAC_KEY_SECRET_FILE="$test_dir/secrets/analyzer_ip_hmac_key"
export CLAWFORGE_GITHUB_TOKEN_FILE="$test_dir/secrets/github_token"
export CLAWFORGE_PROXMOX_TOKEN_FILE="$test_dir/secrets/proxmox_token"
export CLAWFORGE_LINUX_SENSOR_CREDENTIAL_SECRET_FILE="$test_dir/secrets/linux_sensor_credential"
export CLAWFORGE_HAPROXY_SENSOR_CREDENTIAL_SECRET_FILE="$test_dir/secrets/haproxy_sensor_credential"
export CLAWFORGE_DOCKER_SENSOR_CREDENTIAL_SECRET_FILE="$test_dir/secrets/docker_sensor_credential"
export CLAWFORGE_THREATFOX_SECRET_FILE="$test_dir/secrets/threatfox_auth_key"
export CLAWFORGE_URLHAUS_SECRET_FILE="$test_dir/secrets/urlhaus_auth_key"
export CLAWFORGE_MALWAREBAZAAR_SECRET_FILE="$test_dir/secrets/malwarebazaar_auth_key"

"$repo_dir/scripts/validate-secrets.sh" >/dev/null
"$repo_dir/scripts/validate-secrets.sh" --bootstrap >/dev/null
docker compose --env-file /dev/null -f "$repo_dir/compose.yml" config --quiet
docker compose --env-file /dev/null -f "$repo_dir/compose.yml" --profile observability config --quiet
docker compose --env-file /dev/null -f "$repo_dir/compose.yml" --profile agent config --quiet
docker compose --env-file /dev/null -f "$repo_dir/compose.yml" --profile sensors config --quiet
docker compose --env-file /dev/null -f "$repo_dir/compose.yml" -f "$repo_dir/compose.bootstrap.yml" config --quiet

chmod 0644 "$CLAWFORGE_EVENTS_SECRET_FILE"
if "$repo_dir/scripts/validate-secrets.sh" >/dev/null 2>&1; then
  echo "world-readable secret was accepted" >&2
  exit 1
fi
chmod 0600 "$CLAWFORGE_EVENTS_SECRET_FILE"

original_events="$(<"$CLAWFORGE_EVENTS_SECRET_FILE")"
printf '%s\n' 'change-me-events-token-that-is-still-long-enough' >"$CLAWFORGE_EVENTS_SECRET_FILE"
if "$repo_dir/scripts/validate-secrets.sh" >/dev/null 2>&1; then
  echo "placeholder secret was accepted" >&2
  exit 1
fi
printf '%s\n' "$original_events" >"$CLAWFORGE_EVENTS_SECRET_FILE"

original_notifier="$(<"$CLAWFORGE_NOTIFIER_SECRET_FILE")"
cp "$CLAWFORGE_EVENTS_SECRET_FILE" "$CLAWFORGE_NOTIFIER_SECRET_FILE"
if "$repo_dir/scripts/validate-secrets.sh" >/dev/null 2>&1; then
  echo "duplicate internal tokens were accepted" >&2
  exit 1
fi
printf '%s\n' "$original_notifier" >"$CLAWFORGE_NOTIFIER_SECRET_FILE"

rm "$CLAWFORGE_ADMIN_BOOTSTRAP_SECRET_FILE"
"$repo_dir/scripts/validate-secrets.sh" >/dev/null
if "$repo_dir/scripts/validate-secrets.sh" --bootstrap >/dev/null 2>&1; then
  echo "missing one-time bootstrap secret was accepted for bootstrap" >&2
  exit 1
fi

mkdir -p "$test_dir/bin"
apply_mock="$test_dir/bin/docker"
printf '%s\n' '#!/bin/sh' \
  'case "$*" in' \
  '  *pg_dump*) printf "%s" "mock-dump" ;;' \
  '  *pg_restore*) cat >/dev/null; [ "${MOCK_DOCKER_FAIL:-}" != restore ] ;;' \
  '  *) exit 1 ;;' \
  'esac' >"$apply_mock"
chmod 0700 "$apply_mock"

backup_dir="$test_dir/backups"
dump="$(PATH="$test_dir/bin:$PATH" "$repo_dir/scripts/backup.sh" "$backup_dir")"
[ -s "$dump" ]
[ "$(stat -c '%a' "$backup_dir")" = 700 ]
[ "$(stat -c '%a' "$dump")" = 600 ]
[ -z "$(find "$backup_dir" -maxdepth 1 -name '*.tmp' -print -quit)" ]

failed_backup_dir="$test_dir/failed-backups"
if PATH="$test_dir/bin:$PATH" MOCK_DOCKER_FAIL=restore \
  "$repo_dir/scripts/backup.sh" "$failed_backup_dir" >/dev/null 2>&1; then
  echo "invalid backup was accepted" >&2
  exit 1
fi
[ -z "$(find "$failed_backup_dir" -maxdepth 1 -type f -print -quit)" ]

rm "$CLAWFORGE_EVENTS_SECRET_FILE"
if "$repo_dir/scripts/validate-secrets.sh" >/dev/null 2>&1; then
  echo "missing secret was accepted" >&2
  exit 1
fi

echo "secret hardening tests: ok"
