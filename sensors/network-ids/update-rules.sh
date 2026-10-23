#!/usr/bin/env bash
# Update the Suricata ruleset (ET Open, free) safely: download -> validate with the engine -> sanity
# checks -> atomic swap -> live reload. A failed or implausible update leaves the running ruleset
# untouched and is recorded in rules-status.json (freshness is observable, never silently stale).
#
#   update-rules.sh RULES_DIRECTORY [CONTAINER_NAME_TO_RELOAD]
#
# Needs docker, the image local/clawforge-suricata:8.0.7 and outbound HTTPS to the rule source.
# No packet capture, no capabilities, no host network.
set -euo pipefail
RULES="${1:?rules directory}"; RELOAD="${2:-}"
IMAGE="${CLAWFORGE_SURICATA_IMAGE:-local/clawforge-suricata:8.0.7}"
CONF=/opt/clawforge/suricata/suricata.yaml
HERE="$(cd "$(dirname "$0")" && pwd)"
MIN_ENABLED="${CLAWFORGE_SURICATA_MIN_RULES:-10000}"
mkdir -p "$RULES"

# --- ownership model -----------------------------------------------------------------------------
# Staging and work directories are private (mktemp, mode 0700) and owned by the identity that runs
# the containers, so no other local user can enter them, replace the staged ruleset between
# validation, hashing and installation, or plant files. Nothing is ever world- or group-writable.
#   * normal operator (non-root, in the docker group): the containers run as the caller's own
#     UID:GID, the directories already belong to it - no chown, no privilege needed.
#   * root: root-in-a-container is avoided; the containers run as 10001:10001 and the directories
#     are handed to that UID. The chown is REQUIRED: if it fails the update stops.
# The same identity runs updater, validator and cleanup, so the three can never disagree.
if [ "$(id -u)" = 0 ]; then RUN_UID=10001; RUN_GID=10001; else RUN_UID="$(id -u)"; RUN_GID="$(id -g)"; fi
# The installed ruleset is replaced through a path in $RULES: it must not be writable by others.
rmode="$(stat -c %a "$RULES")"
if [ $(( 0$rmode & 022 )) -ne 0 ]; then echo "refusing: $RULES is group- or world-writable (mode $rmode)" >&2; exit 1; fi
STAGE="$(mktemp -d "$RULES/.stage.XXXXXX")"; WORK="$(mktemp -d "$RULES/.work.XXXXXX")"
trap 'rm -rf "$STAGE" "$WORK"' EXIT
if [ "$(id -u)" = 0 ]; then chown "$RUN_UID:$RUN_GID" "$STAGE" "$WORK"; fi   # required; errors abort (set -e)
for d in "$STAGE" "$WORK"; do
  [ "$(stat -c %a "$d")" = 700 ] && [ "$(stat -c %u "$d")" = "$RUN_UID" ] || { echo "unexpected mode/owner on $d" >&2; exit 1; }
done
status() {  # status RESULT DETAIL
  python3 - "$RULES/rules-status.json" "$1" "$2" "${ENABLED:-0}" "${SHA:-}" <<'PY'
import json, sys, time, os
path, result, detail, enabled, sha = sys.argv[1:6]
old = {}
try: old = json.load(open(path))
except (OSError, ValueError): pass
now = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
new = dict(old, last_attempt_at=now, last_result=result, detail=detail)
if result == 'updated':
    new.update(updated_at=now, enabled_rules=int(enabled), ruleset_sha256=sha, source='et/open (suricata-update)')
tmp = path + '.tmp'
open(tmp, 'w').write(json.dumps(new, sort_keys=True)); os.chmod(tmp, 0o644); os.replace(tmp, path)
PY
}
fail() { status failed "$1"; echo "rule update failed: $1 (running rules unchanged)" >&2; exit 1; }

# /etc/suricata (a VOLUME in the upstream image, files 0600 for UID 998) is covered by an empty tmpfs:
# suricata-update then simply skips the optional local classification file and uses the ruleset's.
docker run --rm --user "$RUN_UID:$RUN_GID" --cap-drop ALL --security-opt no-new-privileges --read-only \
  --tmpfs /tmp:rw,size=256m --tmpfs /etc/suricata:rw,size=1m,mode=0755 -e HOME=/tmp \
  -v "$STAGE:/stage" -v "$WORK:/work" \
  -v "$HERE/disable.conf:/disable.conf:ro" --entrypoint suricata-update "$IMAGE" \
  -D /work --suricata-conf "$CONF" -o /stage --no-reload --no-test --disable-conf /disable.conf \
  >"$WORK/update.log" 2>&1 || { tail -5 "$WORK/update.log" >&2; fail "suricata-update"; }
[ -s "$STAGE/suricata.rules" ] || fail "no suricata.rules produced"

# The engine loads suricata.rules AND local.rules from the rules directory: validate exactly that pair.
# local.rules (the self-test canary and site rules) is installed once from the repository if missing.
[ -f "$RULES/local.rules" ] || { cp "$HERE/local.rules" "$RULES/local.rules"; chmod 0644 "$RULES/local.rules"; }
cp "$RULES/local.rules" "$STAGE/local.rules"; chmod 0644 "$STAGE/local.rules"
if [ "$(id -u)" = 0 ]; then chown "$RUN_UID:$RUN_GID" "$STAGE/local.rules"; fi   # required, like the directories

# Validate with the engine itself (offline: no network, no capabilities) using the final config.
docker run --rm --user "$RUN_UID:$RUN_GID" --network none --cap-drop ALL --security-opt no-new-privileges --read-only \
  --tmpfs /tmp:rw,size=256m -v "$STAGE:/rules:ro" --entrypoint /usr/bin/suricata "$IMAGE" \
  -T -c "$CONF" -l /tmp >"$WORK/test.log" 2>&1 || { tail -8 "$WORK/test.log" >&2; fail "engine rejected the ruleset"; }

ENABLED="$(grep -cE '^(alert|drop|reject|pass) ' "$STAGE/suricata.rules" || true)"
[ "$ENABLED" -ge "$MIN_ENABLED" ] || fail "implausibly small ruleset ($ENABLED enabled rules, minimum $MIN_ENABLED)"
if [ -f "$RULES/rules-status.json" ]; then
  PREV="$(python3 -c "import json;print(json.load(open('$RULES/rules-status.json')).get('enabled_rules',0))" 2>/dev/null || echo 0)"
  if [ "$PREV" -gt 0 ] && [ "$ENABLED" -lt $((PREV * 7 / 10)) ]; then fail "ruleset shrank from $PREV to $ENABLED enabled rules (>30%)"; fi
fi
SHA="$(sha256sum "$STAGE/suricata.rules" | cut -d' ' -f1)"

# Atomic swap on the same filesystem; the previous ruleset is kept for a manual rollback.
cp "$STAGE/suricata.rules" "$RULES/suricata.rules.new"; chmod 0644 "$RULES/suricata.rules.new"
[ "$(sha256sum "$RULES/suricata.rules.new" | cut -d' ' -f1)" = "$SHA" ] || { rm -f "$RULES/suricata.rules.new"; fail "installed copy differs from the validated ruleset"; }
[ -f "$RULES/suricata.rules" ] && cp -p "$RULES/suricata.rules" "$RULES/suricata.rules.prev"
mv -T "$RULES/suricata.rules.new" "$RULES/suricata.rules"
status updated "validated by suricata -T"
if [ -n "$RELOAD" ] && docker ps --format '{{.Names}}' | grep -qx "$RELOAD"; then
  docker kill -s USR2 "$RELOAD" >/dev/null && echo "live rule reload requested for $RELOAD"
fi
echo "rules updated: $ENABLED enabled rules, sha256 $SHA"
