#!/usr/bin/env python3
"""Reconcile the labelled behaviour/quality counts from the harness reports. Measures; never passes a gate.

Inputs are the three files written by `scripts/behavior-validation.py` (`behavior-report.json`,
`policy-stage-report.json`, `observables.json`). The confusion matrices are RECOMPUTED from the per-case rows and
compared with the matrices the reports state, so a stale or edited summary cannot hide behind its own totals.

Two different experiments produced the numbers people quote, and they must not be merged:

  * stage 1, "raw anomaly detection": did any rule fire for the case (against the frozen intent label)?
    A false negative here is a missed detection; a false positive is a legitimate case that raised a raw alert.
  * stage 2, "attacker finding": is there a non-observation decision corroborated by an independent source?
    A false negative here is an attack that WAS detected but stays unconfirmed (no enforcement) - not a miss.

The historical counts of the first 15-case baseline (stage 1 before the detection fix) are carried as labelled
history because they cannot be recomputed from current code.

    behavior-reconcile.py --behavior B.json --policy P.json --observables O.json [--out R.json]
"""
import argparse
import json
import os
import sys

SCHEMA = 1
# Carried from docs/behavior-validation.md; different case sets and stages, not comparable with each other.
HISTORY = [
    {"experiment": "baseline-15", "cases": 15, "stage": "stage 1 (raw detection), before the detection fix",
     "tp": 5, "fp": 3, "tn": 5, "fn": 2, "source": "docs/behavior-validation.md, before/after table"},
    {"experiment": "after-fix-15", "cases": 15, "stage": "stage 1, same 15 cases after rule version 2",
     "tp": 7, "fp": 3, "tn": 5, "fn": 0, "source": "same table"},
    {"experiment": "after-fix-18", "cases": 18, "stage": "stage 1", "tp": 10, "fp": 3, "tn": 5, "fn": 0, "source": "same table"},
    {"experiment": "stage2-18", "cases": 18, "stage": "stage 2 (attacker finding)", "tp": 2, "fp": 0, "tn": 8, "fn": 8,
     "source": "same table"},
    {"experiment": "attack-shape-21", "cases": 21, "stage": "stage 1 / stage 2", "stage1": [11, 4, 6, 0], "stage2": [7, 0, 10, 4],
     "source": "docs/behavior-validation.md, attack shape section"},
    {"experiment": "invalid-account-24", "cases": 24, "stage": "stage 1 / stage 2", "stage1": [12, 6, 6, 0], "stage2": [8, 0, 12, 4],
     "source": "docs/behavior-validation.md, invalid user section"},
]


class BadInput(Exception):
    pass


def load(path):
    try:
        with open(path, encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, ValueError) as error:
        raise BadInput(f"{path}: {error}") from error


def matrix(rows):
    out = {"tp": 0, "fp": 0, "tn": 0, "fn": 0}
    for attack, positive in rows:
        out[("tp" if positive else "fn") if attack else ("fp" if positive else "tn")] += 1
    return out


def reconcile(behavior, policy, observables):
    try:
        golden = {c["id"]: c for c in behavior["golden_cases"]}
        stage2 = {c["id"]: c for c in policy["cases"]}
        twins = {}
        for pair in observables["pairs"]:
            twins.setdefault(pair["attack_case"], []).append(pair["legitimate_case"])
            twins.setdefault(pair["legitimate_case"], []).append(pair["attack_case"])
        alerting_legit = set(observables["legitimate_cases_with_a_detector_alert"])
    except (KeyError, TypeError) as error:
        raise BadInput(f"report shape: missing {error}") from error
    if set(golden) != set(stage2):
        raise BadInput("behaviour and policy reports describe different case sets")

    s1 = matrix([(bool(c["label_attack"]), bool(c["alert"])) for c in golden.values()])
    s1_attacker_rules = matrix([(bool(c["label_attack"]), bool(c["attacker_rule_alert"])) for c in golden.values()])
    s2 = matrix([(bool(c["label_attack"]), bool(stage2[i]["attacker_finding_independent_evidence"])) for i, c in golden.items()])
    stated = {"stage1": behavior.get("confusion_matrix"), "stage1_attacker_rules": behavior.get("attacker_rule_matrix"),
              "stage2": {k: policy.get("attacker_finding_matrix", {}).get(k) for k in ("tp", "fp", "tn", "fn")}}
    mismatches = [name for name, mine in (("stage1", s1), ("stage1_attacker_rules", s1_attacker_rules), ("stage2", s2))
                  if any((stated[name] or {}).get(k) != mine[k] for k in mine)]

    requests_for_legit = [i for i, c in golden.items() if not c["label_attack"]
                          and (stage2[i]["enforcement_requests"].get("automatic") or stage2[i]["enforcement_requests"].get("propose"))]
    remaining = {"stage1_false_positives": [], "stage1_false_negatives": [], "stage2_unconfirmed_attacks": []}
    for case_id, c in golden.items():
        if not c["label_attack"] and c["alert"]:
            if not c["attacker_rule_alert"]:
                why = "observation_only_rule: alert of a rule that never reaches a decision above observe"
            elif twins.get(case_id):
                why = "inherent: observably identical to attack case(s) " + ", ".join(sorted(twins[case_id]))
            else:
                why = "no attack twin among the fixtures (so not proven inseparable here); the count threshold fires and nothing else distinguishes it; real populations contain comparable single-name sources (docs/behavior-validation.md)"
            remaining["stage1_false_positives"].append({"case": case_id, "strongest_decision": stage2[case_id]["strongest_decision"],
                                                        "attacker_finding": stage2[case_id]["attacker_finding_independent_evidence"], "classification": why})
        if c["label_attack"] and not c["alert"]:
            remaining["stage1_false_negatives"].append({"case": case_id, "classification": "missed detection"})
        if c["label_attack"] and c["alert"] and not stage2[case_id]["attacker_finding_independent_evidence"]:
            remaining["stage2_unconfirmed_attacks"].append({
                "case": case_id, "strongest_decision": stage2[case_id]["strongest_decision"],
                "classification": ("inherent: observably identical to legitimate case(s) " + ", ".join(sorted(twins[case_id])))
                if twins.get(case_id) else "detected, unconfirmed: no independent evidence in the fixture"})
    unexplained = [r["case"] for r in remaining["stage2_unconfirmed_attacks"] if not r["classification"].startswith("inherent")]
    unexplained += [r["case"] for r in remaining["stage1_false_positives"] if r["classification"].startswith("no attack twin")]
    return {
        "schema": SCHEMA,
        "cases": len(golden),
        "recomputed": {"stage1_raw_detection": s1, "stage1_attacker_rules_only": s1_attacker_rules, "stage2_attacker_finding": s2},
        "stated_matrices_match_recomputed": not mismatches,
        "summary_mismatches": mismatches,
        "quality_gate_passed_recomputed": s1["fp"] == 0 and s1["fn"] == 0,
        "legitimate_cases_with_an_enforcement_request": requests_for_legit,
        "remaining": remaining,
        "needs_an_explanation_beyond_the_fixtures": unexplained,
        "legit_alerting_cases_per_observables_report": sorted(alerting_legit),
        "history_not_recomputable": HISTORY,
        "not_measured": ["false-positive rate on real traffic (no labelled legitimate production bursts exist)",
                         "recall on real attacks (no labelled ground truth)", "behaviour of legitimate shared-NAT users in production"],
        "gate": {"passed": False, "note": "This tool measures only; it never passes or renames a gate."},
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--behavior", required=True)
    parser.add_argument("--policy", required=True)
    parser.add_argument("--observables", required=True)
    parser.add_argument("--out")
    args = parser.parse_args(argv)
    try:
        report = reconcile(load(args.behavior), load(args.policy), load(args.observables))
    except BadInput as error:
        print(json.dumps({"error": str(error), "gate": {"passed": False}}))
        return 2
    text = json.dumps(report, indent=2, sort_keys=True)
    if args.out:
        fd = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text + "\n")
    print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
