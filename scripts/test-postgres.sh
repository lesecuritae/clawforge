#!/usr/bin/env sh
set -eu

container="clawforge-postgres-test"
cleanup() { docker rm -f "$container" >/dev/null 2>&1 || true; }
trap cleanup EXIT INT TERM

docker run --rm -d --name "$container" \
  -e POSTGRES_DB=clawforge_test \
  -e POSTGRES_USER=clawforge \
  -e POSTGRES_PASSWORD=test-password \
  -p 55432:5432 postgres:16-alpine >/dev/null

until docker exec "$container" pg_isready -U clawforge -d clawforge_test >/dev/null 2>&1; do sleep 1; done
CLAWFORGE_TEST_DATABASE_URL='postgres://clawforge:test-password@127.0.0.1:55432/clawforge_test' \
  cargo test -p clawforge-storage --test postgres -- --ignored
