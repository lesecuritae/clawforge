#!/usr/bin/env sh
# Ensures Clawforge's exclusively-owned HAProxy map file exists - the
# direct analog of nftables-clawforge-provision.sh's exclusive table.
#
# Unlike nftables, this script does NOT touch haproxy.cfg itself:
# HAProxy's configuration is a single shared file already serving an
# operator's real frontends (on srv19680: Plex, korbklar_https, ...), so
# Clawforge cannot safely own the whole file the way it owns its own
# nftables table. An operator adds one ACL/action pair to each frontend
# they want protected instead - see the instructions this script prints.
# clawforge-firewall-agent's HaproxyAdapter only ever adds/removes
# *entries* of the map file afterwards, via the Runtime API - it never
# renders or touches haproxy.cfg.
#
# Usage: haproxy-clawforge-provision.sh (run as the user/role that owns
# the HAProxy config directory, typically root or via sudo)
set -eu

map_path="${CLAWFORGE_HAPROXY_BLOCKLIST_ACL_FILE:-/etc/haproxy/maps/clawforge-blocklist.map}"
mkdir -p "$(dirname "$map_path")"
touch "$map_path"

cat >&2 <<EOF
clawforge haproxy map provisioned (or already present): $map_path

Add this to each frontend you want protected - adjust "deny"/"reject" to
the frontend's own mode (http-request deny for an http-mode frontend,
tcp-request connection reject for a tcp-mode one):

    acl clawforge_blocked src -f $map_path
    http-request deny if clawforge_blocked

Then reload HAProxy once (a normal config reload, not something this
script does) so the ACL takes effect. Nothing after that touches
haproxy.cfg again - only the map file's own entries, via the Runtime API.
EOF
