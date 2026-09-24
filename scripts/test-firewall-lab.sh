#!/usr/bin/env sh
# Runs clawforge-firewall-agent's real-nftables tests (#[ignore]-gated,
# "requires nftables (NET_ADMIN/NET_RAW)") inside a disposable, isolated
# container - never against any real deployment host. The container's
# network namespace is created fresh by the container runtime and
# destroyed with it; nothing here can reach, let alone lock anyone out of,
# a real machine's SSH or management access. This is the "isoliertes
# Netzwerk-Lab" the roadmap's phase 6 gate asks for, in the form the tools
# available in this environment can actually provide - see
# docs/firewall-agent.md for what that gate still needs beyond this
# (self-lockout confirmation against a *provisioned* host's real
# management path, which this container has no equivalent of at all).
set -eu

repo_dir="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"

docker run --rm \
  --cap-add=NET_ADMIN --cap-add=NET_RAW \
  -v "$repo_dir:/src" \
  -v /tmp/cf-cargo-target:/src/target \
  -w /src \
  rust:1.98-bookworm \
  sh -c '
    set -eu
    apt-get update -qq >/dev/null
    apt-get install -y -qq nftables >/dev/null
    sh scripts/nftables-clawforge-provision.sh
    cargo test -p clawforge-firewall-agent -- --ignored --test-threads=1
  '
