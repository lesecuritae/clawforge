#!/usr/bin/env bash
# Isolated EQUIVALENT of a guest restart for the passive IDS mirror hook. It is NOT a real guest reboot and does not
# count as the physical validation (docs/live-readiness-audit.md). It runs in a private network namespace
# (`unshare --net --mount`, sysfs remounted privately): no host interface, route, firewall or bridge is touched.
#
# A restarting guest makes its tap devices vanish and reappear (new ifindex). The tc filters live on the tap devices:
#   * source recreated  -> its filter is gone
#   * target recreated  -> the filters on the sources point at a dead ifindex (copies are silently lost)
# The udev rule re-runs `clawforge-ids-mirror up` on every tap "add"; this lab replays exactly that call.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
if [ "${MIRROR_RESTART_LAB_INNER:-}" != 1 ]; then
  exec sudo -n unshare --net --mount env MIRROR_RESTART_LAB_INNER=1 MIRROR_SCRIPT="${MIRROR_SCRIPT:-}" bash "$0" "$@"
fi
# private mount namespace: make /sys show THIS namespace's devices (the mirror script reads /sys/class/net)
mount --make-rprivate /
mount -t sysfs sysfs /sys
M="${MIRROR_SCRIPT:-$HERE/../../sensors/network-ids/host/clawforge-ids-mirror}"
RULE="$HERE/../../sensors/network-ids/host/99-clawforge-ids-mirror.rules"
fail=0
ok() { echo "  PASS $1"; }; bad() { echo "  FAIL $1" >&2; fail=1; }
export MIRROR_TARGET=lt0 MIRROR_SOURCES="ls0"
UP() { sh "$M" up >/dev/null; }          # what the udev rule runs
mkpair() { ip link add "$1" type veth peer name "$2"; ip link set "$1" up; ip link set "$2" up; sysctl -qw net.ipv6.conf."$1".disable_ipv6=1 net.ipv6.conf."$2".disable_ipv6=1; }
rx() { cat /sys/class/net/lt1/statistics/rx_packets; }
send() { python3 - "$1" <<'PY'
import socket, sys
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW); s.bind(("ls1", 0))
frame = b"\xff" * 6 + b"\x02\x00\x00\x00\x00\x01" + b"\x88\xb5" + b"x" * 46   # experimental ethertype: no stack reply
for _ in range(int(sys.argv[1])): s.send(frame)
PY
sleep 0.5; }
copies() { local before; before=$(rx); send "$1"; echo $(( $(rx) - before )); }

# 0. the udev rule triggers exactly this call, on tap devices, on add
grep -q 'ACTION=="add"' "$RULE" && grep -q 'KERNEL=="tap\*"' "$RULE" && grep -q 'clawforge-ids-mirror up"' "$RULE" \
  && ok "udev rule: add of tap* runs 'clawforge-ids-mirror up'" || bad "udev rule does not call 'up' on tap add"
if command -v udevadm >/dev/null 2>&1 && udevadm verify --help >/dev/null 2>&1; then
  udevadm verify --no-style "$RULE" >/dev/null 2>&1 && ok "udevadm verify accepts the rule" || bad "udevadm verify rejects the rule"
fi

mkpair lt0 lt1; mkpair ls0 ls1
UP; UP    # idempotent
[ "$(copies 10)" = 10 ] && ok "baseline: 10 frames -> exactly 10 copies (double up, no duplicates)" || bad "baseline copy count"

# 1. TARGET recreated (sensor VM restarted): new ifindex
old_idx=$(cat /sys/class/net/lt0/ifindex); ip link del lt0; mkpair lt0 lt1
[ "$(cat /sys/class/net/lt0/ifindex)" != "$old_idx" ] && ok "target recreated with a new ifindex" || bad "ifindex unchanged (lab cannot show the failure mode)"
got=$(copies 10); [ "$got" = 0 ] && ok "WITHOUT the hook the copies are lost after the target restart (control: failure mode is real)" || bad "stale filter still mirrored $got (control invalid)"
UP; [ "$(copies 10)" = 10 ] && ok "after 'up' (udev replay) the mirror works again" || bad "not restored after target restart"

# 2. SOURCE recreated (guest restarted): its filter vanished with the device
ip link del ls0; mkpair ls0 ls1
tc filter show dev ls0 ingress 2>/dev/null | grep -q 'pref 4242 ' && bad "filter survived the device" || ok "source filter is gone with the recreated device"
[ "$(copies 10)" = 0 ] && ok "control: no copies before the hook runs" || bad "copies without a filter"
UP; [ "$(copies 10)" = 10 ] && ok "after 'up' the source is mirrored again" || bad "not restored after source restart"

# 3. ordering race: source appears while the target is still absent
ip link del lt0; ip link del ls0; mkpair ls0 ls1
if sh "$M" up >/dev/null 2>&1; then ok "'up' with the target absent exits 0 (unit does not fail)"; else bad "'up' failed with the target absent"; fi
tc filter show dev ls0 ingress 2>/dev/null | grep -q 'pref 4242 ' && bad "filter installed against an absent target" || ok "no filter against an absent target"
mkpair lt0 lt1; UP; [ "$(copies 10)" = 10 ] && ok "target appears later: next 'up' completes the mirror" || bad "race not recovered"

# 4. a foreign filter survives every replay
tc filter add dev ls0 ingress pref 100 protocol arp matchall action pass
UP; UP
tc filter show dev ls0 ingress | grep -q 'pref 100 ' && ok "foreign filter (pref 100) survived the replays" || bad "foreign filter lost"

# 5. rollback: down removes only ours
sh "$M" down >/dev/null
tc filter show dev ls0 ingress 2>/dev/null | grep -q 'pref 4242 ' && bad "our filter left after down" || ok "down removed our filter"
tc filter show dev ls0 ingress | grep -q 'pref 100 ' && ok "down kept the foreign filter" || bad "down removed the foreign filter"
[ "$(copies 10)" = 0 ] && ok "no copies after down" || bad "copies after down"
[ "$fail" -eq 0 ] && echo "MIRROR-RESTART-LAB-OK (isolated equivalent; NOT a real guest reboot)" || { echo "MIRROR-RESTART-LAB-FAILED"; exit 1; }
