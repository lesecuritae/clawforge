#!/usr/bin/env python3
"""Tests for scripts/behavior-reconcile.py (stdlib only; synthetic reports, no database)."""
import importlib.util
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

HERE = pathlib.Path(__file__).parent
spec = importlib.util.spec_from_file_location("rec", HERE / "behavior-reconcile.py")
rec = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rec)


def case(cid, attack, alert, attacker_alert=None):
    return {"id": cid, "label_attack": attack, "alert": alert, "attacker_rule_alert": alert if attacker_alert is None else attacker_alert}


def stage2(cid, attack, finding, decision="challenge", requests=None):
    return {"id": cid, "label_attack": attack, "attacker_finding_independent_evidence": finding, "strongest_decision": decision,
            "enforcement_requests": requests or {"automatic": [], "propose": [], "expected": 0}}


def reports():
    cases = [case("atk_twin", True, True), case("atk_confirmed", True, True), case("atk_missed", True, False),
             case("leg_twin", False, True), case("leg_obs", False, True, attacker_alert=False), case("leg_alone", False, True),
             case("leg_quiet", False, False)]
    behavior = {"golden_cases": cases, "confusion_matrix": rec.matrix([(c["label_attack"], c["alert"]) for c in cases]),
                "attacker_rule_matrix": rec.matrix([(c["label_attack"], c["attacker_rule_alert"]) for c in cases])}
    s2 = [stage2("atk_twin", True, False), stage2("atk_confirmed", True, True, "block"), stage2("atk_missed", True, False, "none"),
          stage2("leg_twin", False, False), stage2("leg_obs", False, False, "observe"), stage2("leg_alone", False, False, "rate_limit"),
          stage2("leg_quiet", False, False, "none")]
    policy = {"cases": s2, "attacker_finding_matrix": rec.matrix([(c["label_attack"], c["attacker_finding_independent_evidence"]) for c in s2])}
    observables = {"pairs": [{"attack_case": "atk_twin", "legitimate_case": "leg_twin", "same_event_shapes": True}],
                   "legitimate_cases_with_a_detector_alert": ["leg_twin", "leg_obs", "leg_alone"]}
    return behavior, policy, observables


class Reconcile(unittest.TestCase):
    def test_matrices_are_recomputed_per_stage_and_not_merged(self):
        r = rec.reconcile(*reports())
        self.assertEqual(r["recomputed"]["stage1_raw_detection"], {"tp": 2, "fp": 3, "tn": 1, "fn": 1})
        self.assertEqual(r["recomputed"]["stage1_attacker_rules_only"]["fp"], 2)
        self.assertEqual(r["recomputed"]["stage2_attacker_finding"], {"tp": 1, "fp": 0, "tn": 4, "fn": 2})
        self.assertTrue(r["stated_matrices_match_recomputed"])

    def test_a_stage2_unconfirmed_attack_is_not_reported_as_a_missed_detection(self):
        r = rec.reconcile(*reports())
        self.assertEqual([x["case"] for x in r["remaining"]["stage1_false_negatives"]], ["atk_missed"])
        unconfirmed = {x["case"]: x["classification"] for x in r["remaining"]["stage2_unconfirmed_attacks"]}
        self.assertEqual(list(unconfirmed), ["atk_twin"])
        self.assertTrue(unconfirmed["atk_twin"].startswith("inherent"))

    def test_each_false_positive_gets_the_right_explanation(self):
        r = rec.reconcile(*reports())
        why = {x["case"]: x["classification"] for x in r["remaining"]["stage1_false_positives"]}
        self.assertTrue(why["leg_twin"].startswith("inherent"))
        self.assertTrue(why["leg_obs"].startswith("observation_only_rule"))
        self.assertTrue(why["leg_alone"].startswith("no attack twin"))
        self.assertEqual(r["needs_an_explanation_beyond_the_fixtures"], ["leg_alone"])

    def test_the_gate_is_never_passed_even_for_a_perfect_run(self):
        behavior, policy, observables = reports()
        for c in behavior["golden_cases"]:
            c["alert"] = c["attacker_rule_alert"] = bool(c["label_attack"])
        for c in policy["cases"]:
            c["attacker_finding_independent_evidence"] = bool(c["label_attack"])
        behavior["confusion_matrix"] = rec.matrix([(c["label_attack"], c["alert"]) for c in behavior["golden_cases"]])
        r = rec.reconcile(behavior, policy, observables)
        self.assertTrue(r["quality_gate_passed_recomputed"])
        self.assertIs(r["gate"]["passed"], False)

    def test_an_edited_summary_cannot_hide_behind_its_own_totals(self):
        behavior, policy, observables = reports()
        behavior["confusion_matrix"] = {"tp": 3, "fp": 0, "tn": 4, "fn": 0}  # claims a better result than the rows show
        r = rec.reconcile(behavior, policy, observables)
        self.assertFalse(r["stated_matrices_match_recomputed"])
        self.assertIn("stage1", r["summary_mismatches"])

    def test_a_legitimate_case_with_an_enforcement_request_is_surfaced(self):
        behavior, policy, observables = reports()
        policy["cases"][3]["enforcement_requests"] = {"automatic": [], "propose": ["waiting_approval"], "expected": 0}
        self.assertEqual(rec.reconcile(behavior, policy, observables)["legitimate_cases_with_an_enforcement_request"], ["leg_twin"])

    def test_history_is_labelled_and_distinct(self):
        names = [h["experiment"] for h in rec.reconcile(*reports())["history_not_recomputable"]]
        self.assertEqual(len(names), len(set(names)))
        base = next(h for h in rec.HISTORY if h["experiment"] == "baseline-15")
        self.assertEqual((base["fp"], base["fn"]), (3, 2))
        final = next(h for h in rec.HISTORY if h["experiment"] == "invalid-account-24")
        self.assertEqual((final["stage1"][1], final["stage2"][3]), (6, 4))

    def test_mismatched_case_sets_and_missing_fields_fail_closed(self):
        behavior, policy, observables = reports()
        with self.assertRaises(rec.BadInput):
            rec.reconcile(behavior, {"cases": policy["cases"][:-1]}, observables)
        with self.assertRaises(rec.BadInput):
            rec.reconcile({"golden_cases": [{"id": "x"}]}, policy, observables)

    def test_cli_exit_codes_and_private_output(self):
        behavior, policy, observables = reports()
        with tempfile.TemporaryDirectory() as tmp:
            tmp = pathlib.Path(tmp)
            for name, doc in (("b.json", behavior), ("p.json", policy), ("o.json", observables)):
                (tmp / name).write_text(json.dumps(doc))
            cmd = [sys.executable, "-I", str(HERE / "behavior-reconcile.py"), "--behavior", str(tmp / "b.json"), "--policy", str(tmp / "p.json"), "--observables", str(tmp / "o.json")]
            ok = subprocess.run(cmd + ["--out", str(tmp / "r.json")], capture_output=True, text=True, timeout=30)
            self.assertEqual(ok.returncode, 0, ok.stderr)
            self.assertEqual((tmp / "r.json").stat().st_mode & 0o777, 0o600)
            (tmp / "b.json").write_text("{broken")
            self.assertEqual(subprocess.run(cmd, capture_output=True, text=True, timeout=30).returncode, 2)


if __name__ == "__main__":
    unittest.main()
