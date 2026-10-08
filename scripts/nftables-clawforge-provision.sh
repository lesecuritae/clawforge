#!/usr/bin/env sh
# One-time provisioning for clawforge-firewall-agent's NftablesAdapter -
# the exclusive table, the two typed sets, and the two rules that actually
# drop traffic. The adapter itself never runs any of this: it only ever
# adds/removes *elements* of these two sets afterwards (see
# firewall-agent/src/lib.rs's own module doc comment for why). Idempotent -
# safe to re-run; every command uses "add" semantics that no-op if the
# object already exists in the exact same shape, and existing set elements
# (if any) are left untouched.
#
# Usage: nftables-clawforge-provision.sh (run as root, or via sudo)
set -eu

# The sets carry `flags interval,timeout`: `interval` for CIDR ranges, and
# `timeout` so each blocked element can carry a native nftables TTL that the
# kernel expires on its own even if the whole Clawforge stack is dead and the
# TTL sweep never runs (P7-4 lockout guard). NOTE: `add set` does not change
# the flags of a set that already exists with a different shape. Upgrading an
# older `flags interval` set to add `timeout` is a one-time manual step:
#   nft delete table inet clawforge   # drops the table, its sets and rules
# then re-run this script. Safe while the live gate is closed (no real block
# is in effect); never do this on a table with live blocks you depend on.
nft add table inet clawforge
nft add chain inet clawforge input '{ type filter hook input priority 0; policy accept; }'
nft add set inet clawforge blocklist '{ type ipv4_addr; flags interval,timeout; }'
nft add set inet clawforge blocklist6 '{ type ipv6_addr; flags interval,timeout; }'

# "add rule" itself is not idempotent (unlike add table/chain/set - each
# call appends a new rule, even a duplicate), so check first: the drop
# rule for each set is recognizable by which set it references.
if ! nft list chain inet clawforge input | grep -q '@blocklist drop'; then
  nft add rule inet clawforge input ip saddr @blocklist drop
fi
if ! nft list chain inet clawforge input | grep -q '@blocklist6 drop'; then
  nft add rule inet clawforge input ip6 saddr @blocklist6 drop
fi

echo "clawforge nftables table/chain/sets/rules provisioned (or already present)"
