#!/usr/bin/env sh
# Controlled offline replay only; never captures a host interface.
set -eu
repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
lab=$(mktemp -d)
trap 'rm -rf "$lab"' EXIT INT TERM
python3 "$repo/tests/network-ids/generate_pcap.py" "$lab"
mkdir "$lab/out"
docker build -f "$repo/sensors/network-ids/Suricata.Dockerfile" -t local/clawforge-suricata:8.0.7 "$repo"
timeout 60 docker run --rm --network none --cap-drop ALL --read-only \
  --user "$(id -u):$(id -g)" \
  --tmpfs /tmp:rw,noexec,nosuid,size=32m \
  -v "$repo/sensors/network-ids/suricata.yaml:/etc/clawforge/suricata.yaml:ro" \
  -v "$lab:/rules:ro" -v "$lab/out:/out" \
  local/clawforge-suricata:8.0.7 -c /etc/clawforge/suricata.yaml \
  --runmode single -r /rules/fixture.pcap -l /out
python3 - "$repo" "$lab/out/eve.json" <<'PY'
import sys,importlib.util,json
from pathlib import Path
spec=importlib.util.spec_from_file_location('adapter',Path(sys.argv[1])/'sensors/network-ids/eve_adapter.py')
a=importlib.util.module_from_spec(spec);spec.loader.exec_module(a)
alerts=[a.normalize(line,'suricata:lab') for line in Path(sys.argv[2]).read_bytes().splitlines()]
alerts=[v for v in alerts if v is not None]
assert len(alerts)==2,alerts
assert all(v['signature_id']==1000001 and v['event_type']=='network_ids_alert' for v in alerts)
print(json.dumps({'packets':3,'controlled_markers':2,'benign':1,'alerts':len(alerts),'network':'none','passed':True}))
PY
