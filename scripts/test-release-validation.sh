#!/usr/bin/env bash
set -Eeuo pipefail

# Full release gate. Live provider requests remain bounded and authenticated
# feeds are skipped unless their keys are injected into this process.
export CLAWFORGE_ENABLE_FEEDS=true

cargo fmt --all -- --check
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings

./scripts/test-provider-smoke.sh
./scripts/test-postgres.sh
./scripts/test-backup-restore.sh

project="clawforge-release-validation-$$"
cleanup() {
  docker compose -p "$project" down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

CLAWFORGE_API_PORT=18080 docker compose -p "$project" config --quiet
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
  /network/trust \
  /metrics; do
  curl --fail --silent "http://127.0.0.1:18080${endpoint}" >/dev/null
done
backup_container="$(docker compose -p "$project" ps -q clawforge-backup)"
until [ -n "$backup_container" ] && docker exec "$backup_container" sh -ec "test -n \"\$(find /backups -maxdepth 1 -name 'clawforge-*.dump' -print -quit)\""; do
  sleep 2
done
echo "release validation: ok"
