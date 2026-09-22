#!/usr/bin/env sh
set -eu

repo_dir="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
container="clawforge-postgres-test"
secret_dir="$(mktemp -d)"
cleanup() {
  docker rm -f "$container" >/dev/null 2>&1 || true
  rm -rf "$secret_dir"
}
trap cleanup EXIT INT TERM

run_cargo() {
  if command -v cargo >/dev/null 2>&1; then
    cargo "$@"
    return
  fi
  mkdir -p "$secret_dir/cargo-home" "$secret_dir/cargo-target"
  docker run --rm --network host \
    --user "$(id -u):$(id -g)" \
    -e CARGO_HOME=/tmp/clawforge-cargo \
    -e CARGO_TARGET_DIR=/tmp/clawforge-target \
    -e DATABASE_URL \
    -e CLAWFORGE_TEST_DATABASE_URL \
    -e CLAWFORGE_TEST_API_DATABASE_URL \
    -e CLAWFORGE_TEST_WORKER_DATABASE_URL \
    -e CLAWFORGE_TEST_CORRELATION_DATABASE_URL \
    -e CLAWFORGE_TEST_INCIDENTS_DATABASE_URL \
    -e CLAWFORGE_TEST_EXECUTOR_DATABASE_URL \
    -e CLAWFORGE_TEST_BACKUP_DATABASE_URL \
    -v "$repo_dir:/src" \
    -v "$secret_dir/cargo-home:/tmp/clawforge-cargo" \
    -v "$secret_dir/cargo-target:/tmp/clawforge-target" \
    -w /src rust:1.98-bookworm cargo "$@"
}

docker run --rm -d --name "$container" \
  -e POSTGRES_DB=clawforge_test \
  -e POSTGRES_USER=clawforge \
  -e POSTGRES_PASSWORD=test-password-012345 \
  -p 55432:5432 postgres:16-alpine >/dev/null

until docker exec "$container" pg_isready -U clawforge -d clawforge_test >/dev/null 2>&1; do sleep 1; done

printf '%s\n' 'test-password-012345' >"$secret_dir/postgres_password"
for role in api worker correlation incidents executor; do
  password="test-${role}-password-0123456789"
  printf '%s\n' "$password" >"$secret_dir/database_${role}_password"
  printf 'postgres://clawforge_%s:%s@127.0.0.1:55432/clawforge_test\n' \
    "$role" "$password" >"$secret_dir/database_${role}_url"
done
backup_password='test-backup-password-0123456789'
printf '%s\n' "$backup_password" >"$secret_dir/database_backup_password"
chmod 600 "$secret_dir"/*

owner_url='postgres://clawforge:test-password-012345@127.0.0.1:55432/clawforge_test'
DATABASE_URL="$owner_url" run_cargo run -q -p clawforge-storage --bin clawforge-migrate

docker run --rm --network host \
  -e PGHOST=127.0.0.1 \
  -e PGPORT=55432 \
  -e POSTGRES_DB=clawforge_test \
  -e POSTGRES_USER=clawforge \
  -e CLAWFORGE_POSTGRES_SECRET_FILE=/run/test-secrets/postgres_password \
  -e CLAWFORGE_DATABASE_API_PASSWORD_SECRET_FILE=/run/test-secrets/database_api_password \
  -e CLAWFORGE_DATABASE_WORKER_PASSWORD_SECRET_FILE=/run/test-secrets/database_worker_password \
  -e CLAWFORGE_DATABASE_CORRELATION_PASSWORD_SECRET_FILE=/run/test-secrets/database_correlation_password \
  -e CLAWFORGE_DATABASE_INCIDENTS_PASSWORD_SECRET_FILE=/run/test-secrets/database_incidents_password \
  -e CLAWFORGE_DATABASE_EXECUTOR_PASSWORD_SECRET_FILE=/run/test-secrets/database_executor_password \
  -e CLAWFORGE_DATABASE_BACKUP_PASSWORD_SECRET_FILE=/run/test-secrets/database_backup_password \
  -v "$secret_dir:/run/test-secrets:ro" \
  -v "$repo_dir/scripts/provision-db-roles.sh:/usr/local/bin/provision-db-roles.sh:ro" \
  postgres:16-alpine sh /usr/local/bin/provision-db-roles.sh

CLAWFORGE_TEST_DATABASE_URL="$owner_url" \
CLAWFORGE_TEST_API_DATABASE_URL="$(cat "$secret_dir/database_api_url")" \
CLAWFORGE_TEST_WORKER_DATABASE_URL="$(cat "$secret_dir/database_worker_url")" \
CLAWFORGE_TEST_CORRELATION_DATABASE_URL="$(cat "$secret_dir/database_correlation_url")" \
CLAWFORGE_TEST_INCIDENTS_DATABASE_URL="$(cat "$secret_dir/database_incidents_url")" \
CLAWFORGE_TEST_EXECUTOR_DATABASE_URL="$(cat "$secret_dir/database_executor_url")" \
CLAWFORGE_TEST_BACKUP_DATABASE_URL="postgres://clawforge_backup:${backup_password}@127.0.0.1:55432/clawforge_test" \
  run_cargo test -p clawforge-storage --test postgres -- --ignored --test-threads=1
