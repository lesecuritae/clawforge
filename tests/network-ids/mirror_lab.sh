#!/usr/bin/env bash
# Lab test of the host mirror script on throw-away namespaces (needs root for ip/tc). Proves:
# exactly-once copies, idempotent up, down removes only our filters, a foreign filter survives,
# a target on a source's bridge is refused, the original traffic is never altered.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; M="$HERE/../../sensors/network-ids/host/clawforge-ids-mirror"
SUDO="${SUDO:-sudo}"; fail=0
ok() { echo "  PASS $1"; }; bad() { echo "  FAIL $1" >&2; fail=1; }
cleanup() { for n in a b; do $SUDO ip netns del mlab$n 2>/dev/null || true; done
  $SUDO ip link del mlbr 2>/dev/null || true; $SUDO ip link del mlt0 2>/dev/null || true; }
trap 'kill ${LISTENER:-0} 2>/dev/null; cleanup' EXIT; cleanup
$SUDO ip link add mlbr type bridge; $SUDO ip link set mlbr up
$SUDO ip link add mlt0 type veth peer name mlt1; $SUDO ip link set mlt0 up; $SUDO ip link set mlt1 up
for n in a b; do
  $SUDO ip netns add mlab$n; $SUDO ip link add m${n}_in type veth peer name m${n}_out
  $SUDO ip link set m${n}_in netns mlab$n; $SUDO ip link set m${n}_out master mlbr; $SUDO ip link set m${n}_out up
  $SUDO ip netns exec mlab$n sh -c "ip addr add 10.97.0.1${n/a/1}${n/b/2}/24 dev m${n}_in 2>/dev/null; ip link set m${n}_in up; ip link set lo up"
done
$SUDO ip netns exec mlaba ip addr flush dev ma_in 2>/dev/null || true
$SUDO ip netns exec mlaba ip addr add 10.97.0.11/24 dev ma_in; $SUDO ip netns exec mlabb ip addr add 10.97.0.12/24 dev mb_in 2>/dev/null || true
# quiet lab: no IPv6 chatter, static neighbours (no ARP), so packet counts are exact
for d in mlt0 mlt1 ma_out mb_out; do $SUDO sysctl -qw net.ipv6.conf.$d.disable_ipv6=1; done
for p in "mlaba ma_in" "mlabb mb_in"; do set -- $p; $SUDO ip netns exec $1 sysctl -qw net.ipv6.conf.$2.disable_ipv6=1; done
mac_a=$($SUDO ip netns exec mlaba cat /sys/class/net/ma_in/address); mac_b=$($SUDO ip netns exec mlabb cat /sys/class/net/mb_in/address)
$SUDO ip netns exec mlaba ip neigh replace 10.97.0.12 lladdr "$mac_b" dev ma_in nud permanent
$SUDO ip netns exec mlabb ip neigh replace 10.97.0.11 lladdr "$mac_a" dev mb_in nud permanent
sleep 2
export MIRROR_TARGET=mlt0 MIRROR_SOURCES="ma_out mb_out"
RUN() { $SUDO env MIRROR_TARGET="$MIRROR_TARGET" MIRROR_SOURCES="$MIRROR_SOURCES" sh "$M" "$@"; }
# a listener on the destination, so no ICMP "port unreachable" replies are generated (those are
# legitimate extra traffic from B and would be mirrored too)
$SUDO ip netns exec mlabb python3 -c 'import socket,time
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(("0.0.0.0",9)); time.sleep(120)' &
LISTENER=$!; sleep 1
count_rx() { cat /sys/class/net/mlt1/statistics/rx_packets; }
send() { $SUDO ip netns exec mlaba python3 -c "
import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
[s.sendto(b'x'*40,('10.97.0.12',9)) for _ in range($1)]"; sleep 1; }

# a foreign filter on one source must survive everything
$SUDO tc qdisc add dev ma_out clsact; $SUDO tc filter add dev ma_out ingress pref 100 protocol arp matchall action pass
base=$(count_rx); send 20; [ "$(( $(count_rx) - base ))" -eq 0 ] && ok "nothing mirrored before up" || bad "mirrored before up"
RUN up >/dev/null; RUN up >/dev/null   # idempotent
base=$(count_rx); send 20; got=$(( $(count_rx) - base ))
[ "$got" -eq 20 ] && ok "20 datagrams -> exactly 20 copies (ingress only, idempotent up)" || bad "expected 20 copies, got $got"
st=$(RUN status); echo "$st" | grep -q "ma_out: mirroring" && ok "status reports mirroring" || bad "status"
$SUDO ip netns exec mlaba ping -c2 -W2 10.97.0.12 >/dev/null && ok "original traffic still forwarded" || bad "traffic broken by mirror"
RUN down >/dev/null
base=$(count_rx); send 20; [ "$(( $(count_rx) - base ))" -eq 0 ] && ok "down stops the copies" || bad "copies after down"
$SUDO tc filter show dev ma_out ingress | grep -q 'pref 100' && ok "foreign filter survived" || bad "foreign filter removed"
$SUDO tc qdisc show dev ma_out | grep -q clsact && ok "shared clsact kept while a foreign filter exists" || bad "clsact removed"
$SUDO tc qdisc show dev mb_out | grep -q clsact && bad "clsact left on a port we created it on" || ok "clsact created by us is removed again"
# a target on a source's bridge is refused (feedback loop)
$SUDO ip link set mlt0 master mlbr
if RUN up 2>/dev/null; then bad "loop target accepted"; else ok "target on a source's bridge refused"; fi
[ "$fail" -eq 0 ] && echo "MIRROR-LAB-OK" || { echo "MIRROR-LAB-FAILED"; exit 1; }
