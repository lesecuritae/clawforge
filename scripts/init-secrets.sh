#!/usr/bin/env bash
set -Eeuo pipefail

umask 077
secret_dir="${1:-./secrets}"
if [ -L "$secret_dir" ]; then
  echo "secret directory must not be a symlink: $secret_dir" >&2
  exit 1
fi
mkdir -p "$secret_dir"
chmod 700 "$secret_dir"

generate_secret() {
  LC_ALL=C od -An -N32 -tx1 /dev/urandom | tr -d ' \n'
}

write_new() {
  local name="$1"
  local value="$2"
  local path="$secret_dir/$name"
  if [ -e "$path" ]; then
    return
  fi
  (umask 077; printf '%s\n' "$value" >"$path")
  chmod 600 "$path"
}

postgres_path="$secret_dir/postgres_password"
database_url_path="$secret_dir/database_url"
if { [ -e "$postgres_path" ] && [ ! -e "$database_url_path" ]; } ||
   { [ ! -e "$postgres_path" ] && [ -e "$database_url_path" ]; }; then
  echo "postgres_password and database_url must either both exist or both be absent" >&2
  exit 1
fi
if [ ! -e "$postgres_path" ]; then
  postgres_password="$(generate_secret)"
  write_new postgres_password "$postgres_password"
  write_new database_url "postgres://clawforge:${postgres_password}@postgres:5432/clawforge"
fi

for name in admin_bootstrap_token analyzer_token notifier_token events_token operations_token mcp_auth_token; do
  write_new "$name" "$(generate_secret)"
done

# This file must be replaced with an Agent API token issued after bootstrap
# before the optional MCP profile is enabled.
write_new mcp_agent_api_token "$(generate_secret)"

for name in analyzer_api_key notifier_webhook_auth notifier_matrix_auth notifier_smtp_password threatfox_auth_key urlhaus_auth_key malwarebazaar_auth_key github_token proxmox_token; do
  write_new "$name" ""
done

find "$secret_dir" -maxdepth 1 -type f ! -name '*.example' -exec chmod 600 {} +
echo "private secret files initialized in $secret_dir (existing files were not overwritten)"
echo "replace mcp_agent_api_token with an issued read-only Agent API token before enabling the agent profile"
