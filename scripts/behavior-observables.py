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


def shape(event):
    def mask(value):
        return re.sub(r"\d+", "#", value) if isinstance(value, str) else value
    return json.dumps({k: mask(v) for k, v in sorted(event.items()) if k not in IGNORED},
                      sort_keys=True)


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
        for attack_id, attack in cases.items():
            if not attack["case"]["label_attack"] or not attack["events"]:
                continue
            attack_shapes = {shape(e) for e in attack["events"]}
            if legit_shapes == attack_shapes:
                pairs.append({
                    "legitimate_case": legit_id, "attack_case": attack_id,
                    "same_event_shapes": True,
                    "legitimate_events": len(legit["events"]),
                    "attack_events": len(attack["events"]),
                    "conclusion": "observably identical apart from count: no deterministic "
                                  "classifier on these fields can separate them; handled by "
                                  "requiring independent evidence before any enforcement",
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
