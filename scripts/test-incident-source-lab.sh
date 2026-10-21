#!/usr/bin/env sh
# Real-kernel lab for the just-in-time incident-source apply (migration 0059):
# a disposable PostgreSQL container plus a Rust container that SHARES its network
# namespace and holds NET_ADMIN, so nftables rules land in that private namespace
# only - never on the host. Needs Docker and network access for apt/crates.
set -eu

repo_dir="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
container="clawforge-incident-lab-pg-$$"
secret_dir="$(mktemp -d)"
cleanup() {
  docker rm -f "$container" >/dev/null 2>&1 || true
  rm -rf "$secret_dir"
}
trap cleanup EXIT INT TERM

docker run --rm -d --name "$container" \
  -e POSTGRES_DB=clawforge_test -e POSTGRES_USER=clawforge \
  -e POSTGRES_PASSWORD=test-password-012345 postgres:16-alpine >/dev/null
until docker exec "$container" pg_isready -h 127.0.0.1 -U clawforge -d clawforge_test >/dev/null 2>&1; do sleep 1; done

printf '%s\n' test-password-012345 >"$secret_dir/postgres_password"
for role in api worker correlation security_engine policy_engine incidents executor operations decision backup; do
  printf '%s\n' "test-${role}-password-0123456789" >"$secret_dir/database_${role}_password"
done
chmod 644 "$secret_dir"/*

# Build caches live in a private per-user directory, not in predictable /tmp paths.
cache_dir="${XDG_CACHE_HOME:-$HOME/.cache}/clawforge-lab"
mkdir -p -m 700 "$cache_dir/target" "$cache_dir/cargo"
docker run --rm --cap-add=NET_ADMIN --cap-add=NET_RAW --network "container:$container" \
  -e CARGO_HOME=/cargo \
  -e PGHOST=127.0.0.1 -e PGPORT=5432 -e POSTGRES_DB=clawforge_test -e POSTGRES_USER=clawforge \
  -e CLAWFORGE_POSTGRES_SECRET_FILE=/secrets/postgres_password \
  -e CLAWFORGE_DATABASE_API_PASSWORD_SECRET_FILE=/secrets/database_api_password \
  -e CLAWFORGE_DATABASE_WORKER_PASSWORD_SECRET_FILE=/secrets/database_worker_password \
  -e CLAWFORGE_DATABASE_CORRELATION_PASSWORD_SECRET_FILE=/secrets/database_correlation_password \
  -e CLAWFORGE_DATABASE_SECURITY_ENGINE_PASSWORD_SECRET_FILE=/secrets/database_security_engine_password \
  -e CLAWFORGE_DATABASE_POLICY_ENGINE_PASSWORD_SECRET_FILE=/secrets/database_policy_engine_password \
  -e CLAWFORGE_DATABASE_INCIDENTS_PASSWORD_SECRET_FILE=/secrets/database_incidents_password \
  -e CLAWFORGE_DATABASE_EXECUTOR_PASSWORD_SECRET_FILE=/secrets/database_executor_password \
  -e CLAWFORGE_DATABASE_OPERATIONS_PASSWORD_SECRET_FILE=/secrets/database_operations_password \
  -e CLAWFORGE_DATABASE_DECISION_PASSWORD_SECRET_FILE=/secrets/database_decision_password \
  -e CLAWFORGE_DATABASE_BACKUP_PASSWORD_SECRET_FILE=/secrets/database_backup_password \
  -v "$repo_dir:/src" -v "$cache_dir/target:/src/target" -v "$cache_dir/cargo:/cargo" \
  -v "$secret_dir:/secrets:ro" -w /src rust:1.98-bookworm sh -c '
    set -eu
    apt-get update -qq >/dev/null
    apt-get install -y -qq nftables iproute2 postgresql-client >/dev/null
    sh scripts/nftables-clawforge-provision.sh
    DATABASE_URL=postgres://clawforge:test-password-012345@127.0.0.1:5432/clawforge_test \
      cargo run -q -p clawforge-storage --bin clawforge-migrate
    sh scripts/provision-db-roles.sh
    export CLAWFORGE_TEST_DATABASE_URL=postgres://clawforge:test-password-012345@127.0.0.1:5432/clawforge_test
    export CLAWFORGE_TEST_EXECUTOR_DATABASE_URL=postgres://clawforge_executor:test-executor-password-0123456789@127.0.0.1:5432/clawforge_test
    cargo test -p clawforge-executor incident_source_real_apply -- --ignored --test-threads=1
  '
