#!/usr/bin/env python3
"""Which labelled-legitimate cases are observably identical to an attack case?

Reads the parser-exported envelopes of a behaviour run (`<case>.json`) and compares
the *shape* of every event: all fields except identifiers that cannot carry intent
(dedupe key, timestamps, the source address) with digit runs masked (`fixture7` ->
`fixture#`, `/fixture-7` -> `/fixture-#`). Two cases with the same set of event
shapes cannot be told apart by any classifier that sees only these fields; the
report states that instead of a verdict. No scenario ID or label is consulted for the
comparison itself; the labels are only used to choose which pairs to print.
"""
import json
import re
import sys
from pathlib import Path

IGNORED = {"dedupe_key", "occurred_at", "resource", "source_ip", "destination_ip"}

# Mirror of the product's attack-shape defaults (policy-engine/src/attack_shape.rs). A name or a
# path is data, not a class: whether "alice" is a legitimate account cannot be known from the
# event, so names and ordinary paths are abstracted away. What a classifier can use is how MANY
# different account names were tried and how many paths match a secret-file signature.
MIN_USERNAMES = 8
MIN_SIGNATURE_PATHS = 3
SECRET_PATHS = [re.compile(p, re.I) for p in (
    r"(^|/)\.env([._-][a-z0-9._-]*)?(\?.*)?$",
    r"(^|/)\.git(/|$|\?)",
    r"(^|/)\.(aws|ssh|docker|svn|hg|kube)(/|$|\?)",
    r"(^|/)\.(npmrc|pypirc|htpasswd|htaccess|netrc|bash_history)(\?.*)?$",
    r"(^|/)aws/(credentials|config)(\?.*)?$",
    r"(^|/)(id_rsa|id_dsa|id_ecdsa|id_ed25519)(\.pub)?(\?.*)?$",
)]


def is_secret_path(path):
    return isinstance(path, str) and any(p.search(path) for p in SECRET_PATHS)


def shape(event):
    def mask(value):
        return re.sub(r"\d+", "#", value) if isinstance(value, str) else value
    fields = {k: mask(v) for k, v in sorted(event.items()) if k not in IGNORED}
    if "username" in fields:
        fields["username"] = "<account>"
    if "path" in fields:
        fields["path"] = "<secret-path>" if is_secret_path(event["path"]) else "<path>"
    return json.dumps(fields, sort_keys=True)


def behaviour(events):
    """The two counts the product derives, from the exported envelopes."""
    users = {str(e["username"]).lower() for e in events if "username" in e}
    secret = {e["path"] for e in events if is_secret_path(e.get("path"))}
    return {"distinct_usernames": len(users), "signature_paths": len(secret),
            "account_enumeration": len(users) >= MIN_USERNAMES,
            "secret_path_probe": len(secret) >= MIN_SIGNATURE_PATHS}


def load(directory):
    cases = {}
    for path in sorted(Path(directory).glob("*.json")):
        try:
            data = json.loads(path.read_text())
        except ValueError:
            continue
        if isinstance(data, dict) and "case" in data and "events" in data:
            cases[data["case"]["id"]] = data
    return cases


def compare(cases, alerting=None):
    """`alerting`: optional set of case IDs the detector raised an anomaly for; when
    given, only those legitimate cases are compared."""
    pairs = []
    for legit_id, legit in cases.items():
        if legit["case"]["label_attack"] or not legit["events"]:
            continue
        if alerting is not None and legit_id not in alerting:
            continue
        legit_shapes = {shape(e) for e in legit["events"]}
        legit_behaviour = behaviour(legit["events"])
        for attack_id, attack in cases.items():
            if not attack["case"]["label_attack"] or not attack["events"]:
                continue
            attack_shapes = {shape(e) for e in attack["events"]}
            attack_behaviour = behaviour(attack["events"])
            flags = ("account_enumeration", "secret_path_probe")
            if legit_shapes == attack_shapes and all(
                    legit_behaviour[f] == attack_behaviour[f] for f in flags):
                pairs.append({
                    "legitimate_case": legit_id, "attack_case": attack_id,
                    "same_event_shapes": True,
                    "legitimate_events": len(legit["events"]),
                    "attack_events": len(attack["events"]),
                    "legitimate_behaviour": legit_behaviour, "attack_behaviour": attack_behaviour,
                    "conclusion": "observably identical apart from count: no deterministic "
                                  "classifier on these fields can separate them (account names and "
                                  "paths abstracted; same account-enumeration and secret-path "
                                  "classes); handled by requiring independent evidence before any "
                                  "enforcement",
                })
    return pairs


def main(argv):
    if len(argv) != 2:
        print("usage: behavior-observables.py REPORT_DIR  (reads behavior-report.json there)",
              file=sys.stderr)
        return 2
    cases = load(argv[1])
    report_path = Path(argv[1]) / "behavior-report.json"
    alerting = None
    if report_path.exists():
        golden = json.loads(report_path.read_text())["golden_cases"]
        alerting = {c["id"] for c in golden if c["alert"] and not c["label_attack"]}
    report = {"pairs": compare(cases, alerting), "cases_compared": len(cases),
              "legitimate_cases_with_a_detector_alert": sorted(alerting) if alerting is not None else None}
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
