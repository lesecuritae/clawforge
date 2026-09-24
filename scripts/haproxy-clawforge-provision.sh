#!/usr/bin/env sh
# Ensures Clawforge's exclusively-owned HAProxy integration points exist -
# the ACL pattern file (clawforge-firewall-agent's HaproxyAdapter, "Maps/
# ACLs") and prints the stick-table config an operator adds for rate
# limiting (HaproxyRateLimitAdapter, "Rate-Limits") - the direct analogs
# of nftables-clawforge-provision.sh's exclusive table, one per HAProxy
# mechanism.
#
# Unlike nftables, this script does NOT touch haproxy.cfg itself:
# HAProxy's configuration is a single shared file already serving an
# operator's real frontends (on srv19680: Plex, korbklar_https, ...), so
# Clawforge cannot safely own the whole file the way it owns its own
# nftables table. An operator adds the ACL/stick-table snippets below to
# each frontend they want protected instead. Neither adapter ever touches
# haproxy.cfg afterwards - only the ACL file's entries or the stick-table's
# per-key counters, via the Runtime API.
#
# Usage: haproxy-clawforge-provision.sh (run as the user/role that owns
# the HAProxy config directory, typically root or via sudo)
set -eu

map_path="${CLAWFORGE_HAPROXY_BLOCKLIST_ACL_FILE:-/etc/haproxy/maps/clawforge-blocklist.map}"
mkdir -p "$(dirname "$map_path")"
touch "$map_path"
rate_limit_table="${CLAWFORGE_HAPROXY_RATE_LIMIT_TABLE:-clawforge_ratelimit}"

cat >&2 <<EOF
clawforge haproxy ACL file provisioned (or already present): $map_path

Add this to each frontend you want protected via HaproxyAdapter ("Maps/
ACLs") - adjust "deny"/"reject" to the frontend's own mode (http-request
deny for an http-mode frontend, tcp-request connection reject for a
tcp-mode one):

    acl clawforge_blocked src -f $map_path
    http-request deny if clawforge_blocked

For HaproxyRateLimitAdapter ("Rate-Limits" - a stick-table's gpc0 counter
rather than a membership list) add one explicitly named backend/table -
"set table"/"show table" over the Runtime API need to address it by an
exact name, which an inline per-frontend stick-table does not reliably
give you - plus a track/ACL pair in each frontend you want protected
(this needs no file - the table is declared in the config itself, and
this exact snippet has been verified against a real HAProxy instance):

    backend $rate_limit_table
        stick-table type ip size 100k expire 1h store gpc0

    # ... inside each frontend you want protected:
    http-request track-sc0 src table $rate_limit_table
    acl clawforge_flagged sc_get_gpc0(0) gt 0
    http-request deny if clawforge_flagged

(Set CLAWFORGE_HAPROXY_RATE_LIMIT_TABLE if you name the backend/table
something other than "$rate_limit_table".)

Then reload HAProxy once (a normal config reload, not something this
script does) so these take effect. Nothing after that touches
haproxy.cfg again - only the ACL file's entries or the stick-table's
per-key gpc0, via the Runtime API.
EOF
