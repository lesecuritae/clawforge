#!/usr/bin/env bash
# End-to-end self-test of the running passive IDS (engine -> EVE -> adapter -> ingress).
#
#   ids-selftest.sh EVE_FILE ADAPTER_STATUS_JSON [DESTINATION_IP] [COUNT]
#
# Sends COUNT UDP datagrams containing only the literal marker CLAWFORGE_IDS_LAB_MARKER to a PRIVATE
# destination (default: this host's default gateway, UDP port 9999). The datagram carries no exploit
# and targets nothing but the local network's own router port; it exists to prove the pipeline,
# not attack coverage. Then checks that
#   1. the engine wrote COUNT new marker alerts (sid 1000001) to the EVE file, and
#   2. the adapter's accepted counter rose by at least COUNT (events reached the authenticated ingress).
# Exit 0 only if both hold. Needs only read access to the two files.
set -euo pipefail
EVE="${1:?EVE file}"; STATUS="${2:?adapter status.json}"; DEST="${3:-}"; COUNT="${4:-5}"
if [ -z "$DEST" ]; then DEST="$(ip route show default | awk '/default/ {print $3; exit}')"; fi
case "$DEST" in 10.*|192.168.*|172.1[6-9].*|172.2?.*|172.3[01].*) ;; *) echo "refusing non-private destination $DEST" >&2; exit 2;; esac
alerts() { grep -c '"signature_id":1000001' "$EVE" 2>/dev/null || true; }
accepted() { python3 -I -c "import json,sys;print(json.load(open('$STATUS'))['adapter'].get('accepted',0))" 2>/dev/null || echo 0; }
a0=$(alerts); s0=$(accepted)
python3 -I - "$DEST" "$COUNT" <<'PY'
import socket, sys, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
for _ in range(int(sys.argv[2])):
    s.sendto(b"CLAWFORGE_IDS_LAB_MARKER", (sys.argv[1], 9999)); time.sleep(0.05)
PY
for _ in $(seq 1 40); do
  sleep 3
  a=$(( $(alerts) - a0 )); s=$(( $(accepted) - s0 ))
  if [ "$a" -ge "$COUNT" ] && [ "$s" -ge "$COUNT" ]; then
    echo "SELFTEST-OK: $a marker alerts in EVE, $s observations accepted by the ingress"; exit 0
  fi
done
echo "SELFTEST-FAILED: engine alerts +$a (want $COUNT), adapter accepted +$s (want >= $COUNT)" >&2; exit 1
