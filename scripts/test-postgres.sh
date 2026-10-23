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
    -e CLAWFORGE_LEARNING_TEST_DATABASE_URL \
    -e CLAWFORGE_TEST_MIGRATION_URL \
    -e CLAWFORGE_TEST_API_DATABASE_URL \
    -e CLAWFORGE_TEST_WORKER_DATABASE_URL \
    -e CLAWFORGE_TEST_CORRELATION_DATABASE_URL \
    -e CLAWFORGE_TEST_SECURITY_ENGINE_DATABASE_URL \
    -e CLAWFORGE_TEST_POLICY_ENGINE_DATABASE_URL \
    -e CLAWFORGE_TEST_INCIDENTS_DATABASE_URL \
    -e CLAWFORGE_TEST_EXECUTOR_DATABASE_URL \
    -e CLAWFORGE_TEST_OPERATIONS_DATABASE_URL \
    -e CLAWFORGE_TEST_DECISION_DATABASE_URL \
    -e CLAWFORGE_TEST_BACKUP_DATABASE_URL \
    -e CLAWFORGE_ANALYZER_ANONYMIZE_IPS \
    -e CLAWFORGE_ANALYZER_IP_HMAC_KEY \
    -v "$repo_dir:/src" \
    -v "$secret_dir/cargo-home:/tmp/clawforge-cargo" \
    -v "$secret_dir/cargo-target:/tmp/clawforge-target" \
    -w /src rust:1.98-bookworm cargo "$@"
}

docker run --rm -d --name "$container" \
  -e POSTGRES_DB=clawforge_test \
  -e POSTGRES_USER=clawforge \
  -e POSTGRES_PASSWORD=test-password-012345 \
  -p 127.0.0.1:55432:5432 postgres:16-alpine >/dev/null

# TCP readiness (-h): the image first serves only a unix socket while it initializes,
# so a socket-only probe can pass just before the final restart.
until docker exec "$container" pg_isready -h 127.0.0.1 -U clawforge -d clawforge_test >/dev/null 2>&1; do sleep 1; done

printf '%s\n' 'test-password-012345' >"$secret_dir/postgres_password"
for role in api worker correlation security_engine policy_engine incidents executor operations decision; do
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
  -e CLAWFORGE_DATABASE_SECURITY_ENGINE_PASSWORD_SECRET_FILE=/run/test-secrets/database_security_engine_password \
  -e CLAWFORGE_DATABASE_POLICY_ENGINE_PASSWORD_SECRET_FILE=/run/test-secrets/database_policy_engine_password \
  -e CLAWFORGE_DATABASE_INCIDENTS_PASSWORD_SECRET_FILE=/run/test-secrets/database_incidents_password \
  -e CLAWFORGE_DATABASE_EXECUTOR_PASSWORD_SECRET_FILE=/run/test-secrets/database_executor_password \
  -e CLAWFORGE_DATABASE_OPERATIONS_PASSWORD_SECRET_FILE=/run/test-secrets/database_operations_password \
  -e CLAWFORGE_DATABASE_DECISION_PASSWORD_SECRET_FILE=/run/test-secrets/database_decision_password \
  -e CLAWFORGE_DATABASE_BACKUP_PASSWORD_SECRET_FILE=/run/test-secrets/database_backup_password \
  -v "$secret_dir:/run/test-secrets:ro" \
  -v "$repo_dir/scripts/provision-db-roles.sh:/usr/local/bin/provision-db-roles.sh:ro" \
  postgres:16-alpine sh /usr/local/bin/provision-db-roles.sh

# Every SECURITY DEFINER function must be callable by some product role after the roles script ran:
# a roles script that lags behind its migration silently disables the caller (release 1.2.3).
orphans="$(docker run --rm -i --network host postgres:16-alpine psql "$owner_url" -At -f - < "$repo_dir/scripts/release/check-role-grants.sql")"
if [ -n "$orphans" ]; then echo "SECURITY DEFINER functions nobody may execute: $orphans" >&2; exit 1; fi

# IP anonymization defaults to on (CLAWFORGE_ANALYZER_ANONYMIZE_IPS) and, with
# no key configured, publish_event now fails closed on any IP-shaped
# correlation id or payload/metadata field - which several fixtures below use
# as a resource. A throwaway key here proves the pseudonymization path itself
# (see storage's ip_pseudonym_tests for the fail-closed case without one).
CLAWFORGE_TEST_DATABASE_URL="$owner_url" \
CLAWFORGE_TEST_API_DATABASE_URL="$(cat "$secret_dir/database_api_url")" \
CLAWFORGE_TEST_WORKER_DATABASE_URL="$(cat "$secret_dir/database_worker_url")" \
CLAWFORGE_TEST_CORRELATION_DATABASE_URL="$(cat "$secret_dir/database_correlation_url")" \
CLAWFORGE_TEST_SECURITY_ENGINE_DATABASE_URL="$(cat "$secret_dir/database_security_engine_url")" \
CLAWFORGE_TEST_POLICY_ENGINE_DATABASE_URL="$(cat "$secret_dir/database_policy_engine_url")" \
CLAWFORGE_TEST_INCIDENTS_DATABASE_URL="$(cat "$secret_dir/database_incidents_url")" \
CLAWFORGE_TEST_EXECUTOR_DATABASE_URL="$(cat "$secret_dir/database_executor_url")" \
CLAWFORGE_TEST_OPERATIONS_DATABASE_URL="$(cat "$secret_dir/database_operations_url")" \
CLAWFORGE_TEST_DECISION_DATABASE_URL="$(cat "$secret_dir/database_decision_url")" \
CLAWFORGE_TEST_BACKUP_DATABASE_URL="postgres://clawforge_backup:${backup_password}@127.0.0.1:55432/clawforge_test" \
CLAWFORGE_ANALYZER_IP_HMAC_KEY="test-only-ip-hmac-key-0123456789-not-for-production" \
  run_cargo test -p clawforge-storage --test postgres -- --ignored --test-threads=1

CLAWFORGE_TEST_DATABASE_URL="$owner_url" \
CLAWFORGE_TEST_CORRELATION_DATABASE_URL="$(cat "$secret_dir/database_correlation_url")" \
CLAWFORGE_TEST_INCIDENTS_DATABASE_URL="$(cat "$secret_dir/database_incidents_url")" \
CLAWFORGE_ANALYZER_IP_HMAC_KEY="test-only-ip-hmac-key-0123456789-not-for-production" \
  run_cargo test -p clawforge-correlation --bin clawforge-correlation -- --ignored --test-threads=1

CLAWFORGE_TEST_DATABASE_URL="$owner_url" \
CLAWFORGE_TEST_SECURITY_ENGINE_DATABASE_URL="$(cat "$secret_dir/database_security_engine_url")" \
CLAWFORGE_TEST_INCIDENTS_DATABASE_URL="$(cat "$secret_dir/database_incidents_url")" \
CLAWFORGE_ANALYZER_IP_HMAC_KEY="test-only-ip-hmac-key-0123456789-not-for-production" \
  run_cargo test -p clawforge-security-engine --bin clawforge-security-engine -- --ignored --test-threads=1 --skip behavioral_tests::

CLAWFORGE_TEST_DATABASE_URL="$owner_url" \
CLAWFORGE_TEST_POLICY_ENGINE_DATABASE_URL="$(cat "$secret_dir/database_policy_engine_url")" \
CLAWFORGE_TEST_SECURITY_ENGINE_DATABASE_URL="$(cat "$secret_dir/database_security_engine_url")" \
CLAWFORGE_ANALYZER_IP_HMAC_KEY="test-only-ip-hmac-key-0123456789-not-for-production" \
  run_cargo test -p clawforge-policy-engine --bin clawforge-policy-engine -- --ignored --test-threads=1 --skip behavior_stage_tests::

CLAWFORGE_TEST_DATABASE_URL="$owner_url" \
CLAWFORGE_ANALYZER_IP_HMAC_KEY="test-only-ip-hmac-key-0123456789-not-for-production" \
  run_cargo test -p clawforge-api --bin clawforge-api -- --ignored --test-threads=1 --skip learning::

# Both reviewed historical migration lineages and quarantine release invariants.
export CLAWFORGE_TEST_MIGRATION_URL="$owner_url"
export CLAWFORGE_TEST_DATABASE_URL="$owner_url"
export CLAWFORGE_TEST_API_DATABASE_URL="$(cat "$secret_dir/database_api_url")"
export CLAWFORGE_TEST_EXECUTOR_DATABASE_URL="$(cat "$secret_dir/database_executor_url")"
export CLAWFORGE_TEST_POLICY_ENGINE_DATABASE_URL="$(cat "$secret_dir/database_policy_engine_url")"
export CLAWFORGE_TEST_WORKER_DATABASE_URL="$(cat "$secret_dir/database_worker_url")"
export CLAWFORGE_TEST_CORRELATION_DATABASE_URL="$(cat "$secret_dir/database_correlation_url")"
run_cargo test -p clawforge-storage --test migration_lineages -- --ignored --test-threads=1
run_cargo test -p clawforge-storage --test quarantine_approval -- --ignored --test-threads=1
run_cargo test -p clawforge-storage --test event_delivery_claim -- --ignored --test-threads=1
run_cargo test -p clawforge-storage --test sensor_metrics -- --ignored --test-threads=1
run_cargo test -p clawforge-storage --test runtime_heartbeat -- --ignored --test-threads=1

export CLAWFORGE_TEST_QUARANTINE_DATABASE_URL="$owner_url"
run_cargo test -p clawforge-storage --test quarantine_intents -- --ignored --test-threads=1
run_cargo test -p clawforge-storage --test quarantine_lease -- --ignored --test-threads=1

run_cargo test -p clawforge-executor native_controller_writeahead_recovery_and_stale_generation_lab -- --ignored --test-threads=1
run_cargo test -p clawforge-executor operator_reconcile_restores_a_recovery_required_docker_generation_lab -- --ignored --test-threads=1

run_cargo test -p clawforge-storage --test dispatch_recovery -- --ignored --test-threads=1
run_cargo test -p clawforge-storage --test incident_source_resolution -- --ignored --test-threads=1
run_cargo test -p clawforge-storage --test policy_bridge -- --ignored --test-threads=1
run_cargo test -p clawforge-storage --test source_intel -- --ignored --test-threads=1
run_cargo test -p clawforge-worker --test ip_context -- --ignored --test-threads=1
run_cargo test -p clawforge-worker --test network_events -- --ignored --test-threads=1

export CLAWFORGE_TEST_FIREWALL_RULE_DATABASE_URL="$owner_url"
run_cargo test -p clawforge-storage --test firewall_rule_intents -- --ignored --test-threads=1
run_cargo test -p clawforge-executor firewall_rule_recovery_retains_ownership_without_blind_replay -- --ignored --test-threads=1

# Structured learning is a required real PostgreSQL gate, not an ignored test
# silently left out of CI. Run its dedicated fixture cases after legacy gates.
export CLAWFORGE_LEARNING_TEST_DATABASE_URL="$owner_url"
run_cargo test -p clawforge-storage --test learning -- --include-ignored --test-threads=1
run_cargo test -p clawforge-api --bin clawforge-api learning:: -- --include-ignored --test-threads=1

# Trusted CI verifier/operator integration uses its own nested disposable DB.
run_cargo test -p clawforge-storage --bin learning-trust -- --include-ignored --test-threads=1
