#!/usr/bin/env bash
# Real end-to-end test of update-rules.sh ownership and isolation (needs docker, outbound HTTPS to the
# rule source, and sudo for the "other user" probe). Proves:
#   1. a normal (non-root) update installs a validated ruleset atomically (real download, real
#      `suricata -T`), with private 0700 staging directories owned by the caller;
#   2. while the update runs, another local user is actually denied entering/writing the staging
#      directories (probes are attempted continuously and must all fail, at least one must run);
#   3. a group/world-writable rules directory is refused before anything is staged;
#   4. an update as root works too (containers run as 10001, directories handed over by a required
#      chown) and leaves nothing behind.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; U="$HERE/../../sensors/network-ids/update-rules.sh"
OTHER="${OTHER_USER:-nobody}"; fail=0
ok() { echo "  PASS $1"; }; bad() { echo "  FAIL $1" >&2; fail=1; }
W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT; chmod 755 "$W"

probe() {  # $1 = rules dir; runs until $2 (flag file) exists; logs one line per attempt
  while [ ! -e "$2" ]; do
    for d in "$1"/.stage.* "$1"/.work.*; do
      [ -d "$d" ] || continue
      if sudo -n -u "$OTHER" sh -c "touch '$d/evil' 2>/dev/null || ls '$d' >/dev/null 2>&1"; then echo "ALLOWED $d" >> "$W/probe.log"
      else echo "DENIED $d" >> "$W/probe.log"; fi
    done
    sleep 0.3
  done
}

# 1+2: non-root update with a concurrent hostile local user
R="$W/rules"; mkdir -p "$R"; chmod 755 "$R"
: > "$W/probe.log"; rm -f "$W/done"; probe "$R" "$W/done" & PROBE=$!
bash "$U" "$R" > "$W/u1.log" 2>&1; rc=$?; touch "$W/done"; wait "$PROBE" 2>/dev/null
[ "$rc" -eq 0 ] && ok "non-root update succeeded (download, suricata -T, atomic install)" || { bad "non-root update failed"; tail -5 "$W/u1.log" >&2; }
grep -q 'enabled rules' "$W/u1.log" && [ -s "$R/suricata.rules" ] && ok "ruleset installed" || bad "no ruleset installed"
python3 -I -c "import json,sys;d=json.load(open('$R/rules-status.json'));sys.exit(0 if d['last_result']=='updated' and d['enabled_rules']>10000 else 1)" && ok "status records the update" || bad "status file"
denied=$(grep -c '^DENIED' "$W/probe.log" || true); allowed=$(grep -c '^ALLOWED' "$W/probe.log" || true)
[ "$denied" -ge 2 ] && [ "$allowed" -eq 0 ] && ok "other local user denied on every attempt ($denied attempts, 0 allowed)" || bad "cross-user probe: denied=$denied allowed=$allowed"
[ -z "$(ls -A "$R" | grep -E '^\.(stage|work)\.')" ] && ok "staging directories removed" || bad "staging left behind"

# 3: unsafe rules directory is refused before staging
R2="$W/unsafe"; mkdir -p "$R2"; chmod 777 "$R2"
bash "$U" "$R2" > "$W/u2.log" 2>&1 && bad "world-writable rules directory accepted" || { grep -q 'group- or world-writable' "$W/u2.log" && [ -z "$(ls -A "$R2")" ] && ok "world-writable rules directory refused, nothing staged"; }
chmod 775 "$R2"; bash "$U" "$R2" > "$W/u2b.log" 2>&1 && bad "group-writable rules directory accepted" || ok "group-writable rules directory refused"

# 4: root update
R3="$W/rules-root"; sudo -n mkdir -p "$R3"; sudo -n chmod 755 "$R3"
sudo -n bash "$U" "$R3" > "$W/u3.log" 2>&1; rc=$?
[ "$rc" -eq 0 ] && [ -s "$R3/suricata.rules" ] && ok "root update succeeded (containers as 10001, required chown)" || { bad "root update failed"; tail -5 "$W/u3.log" >&2; }
[ -z "$(sudo -n ls -A "$R3" | grep -E '^\.(stage|work)\.')" ] && ok "root run left no staging directories" || bad "root staging left behind"
sudo -n rm -rf "$R3"
[ "$fail" -eq 0 ] && echo "UPDATE-RULES-SECURITY-OK" || { echo "UPDATE-RULES-SECURITY-FAILED"; exit 1; }
