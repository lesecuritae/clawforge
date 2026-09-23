#!/usr/bin/env bash
set -Eeuo pipefail

case "${1:-}" in
  "") require_bootstrap=false ;;
  --bootstrap) require_bootstrap=true ;;
  *) echo "usage: $0 [--bootstrap]" >&2; exit 2 ;;
esac

declare -A paths=(
  [postgres_password]="${CLAWFORGE_POSTGRES_SECRET_FILE:-./secrets/postgres_password}"
  [database_url]="${CLAWFORGE_DATABASE_URL_SECRET_FILE:-./secrets/database_url}"
  [database_api_password]="${CLAWFORGE_DATABASE_API_PASSWORD_SECRET_FILE:-./secrets/database_api_password}"
  [database_api_url]="${CLAWFORGE_DATABASE_API_URL_SECRET_FILE:-./secrets/database_api_url}"
  [database_worker_password]="${CLAWFORGE_DATABASE_WORKER_PASSWORD_SECRET_FILE:-./secrets/database_worker_password}"
  [database_worker_url]="${CLAWFORGE_DATABASE_WORKER_URL_SECRET_FILE:-./secrets/database_worker_url}"
  [database_correlation_password]="${CLAWFORGE_DATABASE_CORRELATION_PASSWORD_SECRET_FILE:-./secrets/database_correlation_password}"
  [database_correlation_url]="${CLAWFORGE_DATABASE_CORRELATION_URL_SECRET_FILE:-./secrets/database_correlation_url}"
  [database_security_engine_password]="${CLAWFORGE_DATABASE_SECURITY_ENGINE_PASSWORD_SECRET_FILE:-./secrets/database_security_engine_password}"
  [database_security_engine_url]="${CLAWFORGE_DATABASE_SECURITY_ENGINE_URL_SECRET_FILE:-./secrets/database_security_engine_url}"
  [database_incidents_password]="${CLAWFORGE_DATABASE_INCIDENTS_PASSWORD_SECRET_FILE:-./secrets/database_incidents_password}"
  [database_incidents_url]="${CLAWFORGE_DATABASE_INCIDENTS_URL_SECRET_FILE:-./secrets/database_incidents_url}"
  [database_executor_password]="${CLAWFORGE_DATABASE_EXECUTOR_PASSWORD_SECRET_FILE:-./secrets/database_executor_password}"
  [database_executor_url]="${CLAWFORGE_DATABASE_EXECUTOR_URL_SECRET_FILE:-./secrets/database_executor_url}"
  [database_backup_password]="${CLAWFORGE_DATABASE_BACKUP_PASSWORD_SECRET_FILE:-./secrets/database_backup_password}"
  [admin_bootstrap_token]="${CLAWFORGE_ADMIN_BOOTSTRAP_SECRET_FILE:-./secrets/admin_bootstrap_token}"
  [analyzer_token]="${CLAWFORGE_ANALYZER_SECRET_FILE:-./secrets/analyzer_token}"
  [analyzer_api_key]="${CLAWFORGE_ANALYZER_API_KEY_SECRET_FILE:-./secrets/analyzer_api_key}"
  [notifier_token]="${CLAWFORGE_NOTIFIER_SECRET_FILE:-./secrets/notifier_token}"
  [notifier_webhook_auth]="${CLAWFORGE_NOTIFICATION_WEBHOOK_SECRET_FILE:-./secrets/notifier_webhook_auth}"
  [notifier_matrix_auth]="${CLAWFORGE_NOTIFICATION_MATRIX_SECRET_FILE:-./secrets/notifier_matrix_auth}"
  [notifier_smtp_password]="${CLAWFORGE_NOTIFICATION_SMTP_SECRET_FILE:-./secrets/notifier_smtp_password}"
  [events_token]="${CLAWFORGE_EVENTS_SECRET_FILE:-./secrets/events_token}"
  [operations_token]="${CLAWFORGE_OPERATIONS_SECRET_FILE:-./secrets/operations_token}"
  [mcp_agent_api_token]="${CLAWFORGE_MCP_AGENT_TOKEN_FILE:-./secrets/mcp_agent_api_token}"
  [mcp_auth_token]="${CLAWFORGE_MCP_AUTH_TOKEN_FILE:-./secrets/mcp_auth_token}"
  [analyzer_ip_hmac_key]="${CLAWFORGE_ANALYZER_IP_HMAC_KEY_SECRET_FILE:-./secrets/analyzer_ip_hmac_key}"
  [github_token]="${CLAWFORGE_GITHUB_TOKEN_FILE:-./secrets/github_token}"
  [proxmox_token]="${CLAWFORGE_PROXMOX_TOKEN_FILE:-./secrets/proxmox_token}"
  [linux_sensor_credential]="${CLAWFORGE_LINUX_SENSOR_CREDENTIAL_SECRET_FILE:-./secrets/linux_sensor_credential}"
  [haproxy_sensor_credential]="${CLAWFORGE_HAPROXY_SENSOR_CREDENTIAL_SECRET_FILE:-./secrets/haproxy_sensor_credential}"
  [docker_sensor_credential]="${CLAWFORGE_DOCKER_SENSOR_CREDENTIAL_SECRET_FILE:-./secrets/docker_sensor_credential}"
  [threatfox_auth_key]="${CLAWFORGE_THREATFOX_SECRET_FILE:-./secrets/threatfox_auth_key}"
  [urlhaus_auth_key]="${CLAWFORGE_URLHAUS_SECRET_FILE:-./secrets/urlhaus_auth_key}"
  [malwarebazaar_auth_key]="${CLAWFORGE_MALWAREBAZAAR_SECRET_FILE:-./secrets/malwarebazaar_auth_key}"
)

fail() {
  echo "secret preflight failed: $*" >&2
  exit 1
}

read_value() {
  tr -d '\r\n' <"$1"
}

is_placeholder() {
  local value
  value="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')"
  [[ "$value" == *change-me* || "$value" == *changeme* ||
     "$value" == *replace-this* || "$value" == *replace-with* ||
     "$value" == *placeholder* || "$value" == *example-token* ]]
}

validate_token() {
  local name="$1"
  local value="$2"
  [ "${#value}" -ge 32 ] || fail "$name must contain at least 32 characters"
  [[ "$value" != *[[:space:]]* ]] || fail "$name must not contain whitespace"
  is_placeholder "$value" && fail "$name contains a known placeholder"
  local diversity
  diversity="$(printf '%s' "$value" | fold -w1 | LC_ALL=C sort -u | wc -l)"
  [ "$diversity" -ge 8 ] || fail "$name has insufficient character diversity"
}

for name in "${!paths[@]}"; do
  if [ "$name" = admin_bootstrap_token ] && [ "$require_bootstrap" = false ]; then
    continue
  fi
  path="${paths[$name]}"
  [[ "$path" != *.example ]] || fail "$name points to a checked-in example file"
  [ ! -L "$path" ] || fail "$name must not be a symlink"
  [ -f "$path" ] || fail "$name file is missing or not regular: $path"
  owner="$(stat -c '%u' "$path")"
  [ "$owner" = "$(id -u)" ] || fail "$name must be owned by the deployment user"
  mode="$(stat -c '%a' "$path")"
  permissions=$((8#$mode))
  [ $((permissions & 8#077)) -eq 0 ] || fail "$name permissions must not grant group/other access"
done

postgres_password="$(read_value "${paths[postgres_password]}")"
[ "${#postgres_password}" -ge 16 ] || fail "postgres_password must contain at least 16 characters"
[[ "$postgres_password" =~ ^[A-Za-z0-9._~-]+$ ]] ||
  fail "postgres_password must contain only URL-safe password characters"
is_placeholder "$postgres_password" && fail "postgres_password contains a known placeholder"

database_url="$(read_value "${paths[database_url]}")"
[[ "$database_url" == postgres://* || "$database_url" == postgresql://* ]] ||
  fail "database_url must use the postgres or postgresql scheme"
is_placeholder "$database_url" && fail "database_url contains a known placeholder"
[[ "$database_url" == *":${postgres_password}@"* ]] ||
  fail "database_url does not contain the matching postgres password"

database_password_names=()
for role in api worker correlation incidents executor; do
  password_name="database_${role}_password"
  url_name="database_${role}_url"
  password="$(read_value "${paths[$password_name]}")"
  [ "${#password}" -ge 16 ] || fail "$password_name must contain at least 16 characters"
  [[ "$password" != *[[:space:]]* ]] || fail "$password_name must not contain whitespace"
  [[ "$password" =~ ^[A-Za-z0-9._~-]+$ ]] ||
    fail "$password_name must contain only URL-safe password characters"
  is_placeholder "$password" && fail "$password_name contains a known placeholder"
  [ "$password" != "$postgres_password" ] || fail "$password_name must differ from postgres_password"
  url="$(read_value "${paths[$url_name]}")"
  [[ "$url" == "postgres://clawforge_${role}:"* || "$url" == "postgresql://clawforge_${role}:"* ]] ||
    fail "$url_name must use its dedicated clawforge_${role} PostgreSQL role"
  [[ "$url" == *":${password}@"* ]] || fail "$url_name does not contain the matching role password"
  is_placeholder "$url" && fail "$url_name contains a known placeholder"
  database_password_names+=("$password_name")
done
backup_password="$(read_value "${paths[database_backup_password]}")"
[ "${#backup_password}" -ge 16 ] || fail "database_backup_password must contain at least 16 characters"
[[ "$backup_password" =~ ^[A-Za-z0-9._~-]+$ ]] ||
  fail "database_backup_password must contain only URL-safe password characters"
is_placeholder "$backup_password" && fail "database_backup_password contains a known placeholder"
[ "$backup_password" != "$postgres_password" ] ||
  fail "database_backup_password must differ from postgres_password"
database_password_names+=(database_backup_password)
for ((left = 0; left < ${#database_password_names[@]}; left++)); do
  for ((right = left + 1; right < ${#database_password_names[@]}; right++)); do
    left_name="${database_password_names[$left]}"
    right_name="${database_password_names[$right]}"
    [ "$(read_value "${paths[$left_name]}")" != "$(read_value "${paths[$right_name]}")" ] ||
      fail "$left_name and $right_name must use different credentials"
  done
done

token_names=(analyzer_token notifier_token events_token operations_token mcp_agent_api_token mcp_auth_token analyzer_ip_hmac_key)
if [ "$require_bootstrap" = true ]; then
  token_names+=(admin_bootstrap_token)
fi
declare -A token_values
for name in "${token_names[@]}"; do
  token_values[$name]="$(read_value "${paths[$name]}")"
  validate_token "$name" "${token_values[$name]}"
done
for ((left = 0; left < ${#token_names[@]}; left++)); do
  for ((right = left + 1; right < ${#token_names[@]}; right++)); do
    left_name="${token_names[$left]}"
    right_name="${token_names[$right]}"
    [ "${token_values[$left_name]}" != "${token_values[$right_name]}" ] ||
      fail "$left_name and $right_name must use different credentials"
  done
done

echo "secret preflight: ok"
