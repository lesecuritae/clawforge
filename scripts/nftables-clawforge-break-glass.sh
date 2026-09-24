#!/usr/bin/env sh
# Emergency removal of ALL Clawforge nftables state - the "break-glass"
# procedure the roadmap's phase 6 Pflichtgates ask for
# (docs/security-control-plane-roadmap.de.md). Run this directly on the
# affected host, over SSH, independent of clawforge-executor, the API, or
# Postgres being reachable or even running at all - this script has no
# dependency on any of them, on purpose.
#
# What it does: deletes Clawforge's one exclusive table (`inet clawforge`)
# in a single atomic `nft delete table` call. Since NftablesAdapter (see
# firewall-agent/src/lib.rs) never renders anything outside that one
# table - no rule, no set, nothing - deleting it undoes 100% of
# Clawforge's nftables footprint on this host at once, with zero risk to
# any other rule, table, or chain: `nft delete table` only ever touches
# the named table.
#
# This is a full stop, not a selective rollback: after running this,
# Clawforge blocks nothing on this host at all until the table is
# reprovisioned (scripts/nftables-clawforge-provision.sh) and the
# executor's own current desired state is re-applied. Use it when a
# selective per-target rollback (FirewallAdapter::rollback, or the
# executor's normal TTL expiry) is not enough - suspected self-lockout, a
# malfunctioning executor applying targets it should not, or any
# situation where "stop everything Clawforge did to this host's firewall,
# right now" is the correct response.
#
# Rehearsed (not just documented): scripts/test-firewall-lab.sh's
# break-glass round-trip test provisions the table, blocks a target,
# breaks glass, and asserts the table and every element in it are gone -
# in the same disposable, isolated container every other real-nftables
# test in this crate uses, never against a real deployment host.
set -eu

if nft list table inet clawforge >/dev/null 2>&1; then
    nft delete table inet clawforge
    echo "clawforge break-glass: table inet clawforge removed - Clawforge blocks nothing on this host until it is reprovisioned." >&2
else
    echo "clawforge break-glass: table inet clawforge was not present - nothing to remove." >&2
fi
