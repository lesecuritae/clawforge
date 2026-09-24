#!/usr/bin/env sh
# Runs clawforge-firewall-agent's real-HAProxy tests (#[ignore]-gated,
# "requires a real HAProxy Runtime API socket") inside a disposable
# container - never against srv19680 or any other real deployment host.
# Installs haproxy, provisions Clawforge's map file
# (scripts/haproxy-clawforge-provision.sh), starts a minimal
# self-contained haproxy instance (its own throwaway frontend/backend,
# not any real deployment's config) with the Runtime API socket enabled,
# waits for the socket to appear, then runs the tests against it. Unlike
# the nftables lab, this needs no special capabilities (no NET_ADMIN/
# NET_RAW) - the Runtime API is a plain Unix domain socket and the test
# frontend only ever binds a local port inside the container.
set -eu

repo_dir="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"

docker run --rm \
  -v "$repo_dir:/src" \
  -v /tmp/cf-cargo-target:/src/target \
  -w /src \
  rust:1.98-bookworm \
  sh -c '
    set -eu
    apt-get update -qq >/dev/null
    apt-get install -y -qq haproxy >/dev/null

    export CLAWFORGE_HAPROXY_ADMIN_SOCKET=/tmp/clawforge-haproxy-admin.sock
    export CLAWFORGE_HAPROXY_BLOCKLIST_ACL_FILE=/tmp/clawforge-blocklist.map
    sh scripts/haproxy-clawforge-provision.sh

    cat > /tmp/clawforge-haproxy-test.cfg <<CFG
global
    stats socket ${CLAWFORGE_HAPROXY_ADMIN_SOCKET} mode 660 level admin

defaults
    mode http
    timeout connect 5s
    timeout client 5s
    timeout server 5s

frontend clawforge_test
    bind 127.0.0.1:18080
    acl clawforge_blocked src -f ${CLAWFORGE_HAPROXY_BLOCKLIST_ACL_FILE}
    http-request deny if clawforge_blocked
    default_backend clawforge_test_backend

backend clawforge_test_backend
    server placeholder 127.0.0.1:65535
CFG

    haproxy -f /tmp/clawforge-haproxy-test.cfg -D

    tries=0
    while [ ! -S "${CLAWFORGE_HAPROXY_ADMIN_SOCKET}" ]; do
      tries=$((tries + 1))
      if [ "$tries" -gt 50 ]; then
        echo "haproxy admin socket never appeared" >&2
        exit 1
      fi
      sleep 0.1
    done

    cargo test -p clawforge-firewall-agent -- --ignored --test-threads=1 haproxy
  '
