#!/usr/bin/env python3
"""Tests for scripts/phase7b-observe.py (stdlib only, no network, no host access)."""
import importlib.util
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest
import copy

HERE = pathlib.Path(__file__).parent
spec = importlib.util.spec_from_file_location("p7b", HERE / "phase7b-observe.py")
p7b = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p7b)

START = p7b.parse_time("2026-10-26T08:00:00Z")
HOURS = 48
END = START + HOURS * 3600
GOOD = {"unresolved_generations": 0, "executable_requests": 0, "active_elements": {"blocklist": 0, "blocklist6": 0},
        "running_executors": [], "api_healthy": True}
ARGV = ["true"]


def plan(confirmed=True, **criteria):
    value = p7b.build_plan(START, HOURS, ARGV, criteria=criteria)
    if confirmed:
        value["operator_confirmed_by"] = "operator"
    return value


def cycle(i, ok=True, ts=None, data=None, attempts=None):
    ts = START + 60 * i if ts is None else ts
    return {"timestamp": ts, "cycle": i + 1, "ssh_ok": ok, "data": (data or GOOD) if ok else {},
            "attempts": attempts or [{"attempt": 1, "ok": ok}], "issues": [] if ok else ["telemetry_unavailable"]}


def window(fail_at=(), n=None):
    n = n or HOURS * 60
    return [cycle(i, ok=i not in fail_at) for i in range(n)]


def canary(i, **kw):
    row = {"type": "canary", "request_id": f"r{i}", "lab": False, "distinct_human_approvals": 2, "baseline_ok": True,
           "blocked_dropped": True, "restored_ok": True, "rollback_seconds": 2.0 + (i % 3), "receipt_after_deadline_seconds": 1.5}
    row.update(kw)
    return row


def full_measurements():
    rows = [canary(i) for i in range(10)]
    rows += [{"type": "lockout_probe", "protected_address": f"10.0.0.{i}", "refused": True} for i in range(20)]
    rows += [{"type": "drift_injection", "injected_at": 100.0 + i, "detected_at": 105.0 + i} for i in range(3)]
    rows += [{"type": "false_positive_review", "label_source": "operator", "classification": "malicious", "was_blocked": True} for _ in range(5)]
    return rows


def status(samples, measurements=(), now=END + 10, p=None):
    return p7b.evaluate(p or plan(), samples, list(measurements), now)


def crit(report, name):
    return next(c for c in report["criteria"] if c["criterion"] == name)["status"]


OPERATOR_ID = "00000000-0000-0000-0000-000000000099"
SOLO_PROFILE = {"mode": "single_operator", "operator_user_id": OPERATOR_ID,
                "allowed_actions": ["nftables.block_incident_source"]}


def solo_plan():
    value = plan()
    value["approval_profile"] = copy.deepcopy(SOLO_PROFILE)
    value["plan_sha256"] = p7b.canonical_hash(value)
    return value


def solo_canary(i):
    request = f"00000000-0000-0000-0001-{i + 1:012d}"
    return canary(i, request_id=request, distinct_human_approvals=1,
                  action="nftables.block_incident_source", required_approvals=1,
                  approval_profile={"mode": "single_operator", "operator_user_id": OPERATOR_ID},
                  approval_context_hash="a" * 64,
                  approval_evidence={"execution_id": request, "approver_id": OPERATOR_ID,
                                     "approval_mode": "single_operator_confirmation", "context_hash": "a" * 64})


class SingleOperatorTests(unittest.TestCase):
    def test_legacy_registered_plan_keeps_default_and_original_hash(self):
        value = plan()
        value.pop("approval_profile", None)
        value["plan_sha256"] = p7b.canonical_hash(value)
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "legacy.json"
            path.write_text(json.dumps(value))
            loaded = p7b.load_plan(path)
        self.assertEqual(loaded["plan_sha256"], value["plan_sha256"])
        self.assertEqual(crit(status(window(), full_measurements(), p=loaded), "rollback_p95"), "met")
        self.assertEqual(crit(status(window(), [solo_canary(i) for i in range(10)], p=loaded), "rollback_p95"), "not_measured")

    def test_cli_freezes_native_profile_file_and_keeps_operator_confirmation_empty(self):
        with tempfile.TemporaryDirectory() as tmp:
            profile = pathlib.Path(tmp) / "profile.json"
            profile.write_text(json.dumps(SOLO_PROFILE))
            out = pathlib.Path(tmp) / "plan.json"
            args = [sys.executable, str(HERE / "phase7b-observe.py"), "plan", "--out", str(out),
                    "--start", "2026-10-26T08:00:00Z", "--probe-argv-json", '["true"]',
                    "--approval-profile-file", str(profile)]
            result = subprocess.run(args, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            loaded = p7b.load_plan(out)
            self.assertEqual(loaded["approval_profile"], SOLO_PROFILE)
            self.assertIsNone(loaded["operator_confirmed_by"])
            self.assertEqual(out.stat().st_mode & 0o777, 0o600)
            profile.write_text(json.dumps({"mode": "automatic"}))
            self.assertEqual(p7b.load_plan(out)["approval_profile"], SOLO_PROFILE)
            args[args.index("--out") + 1] = str(pathlib.Path(tmp) / "invalid.json")
            for contents in ("{broken", '{"mode":"automatic"}'):
                profile.write_text(contents)
                self.assertEqual(subprocess.run(args, capture_output=True).returncode, 2)
            profile.unlink()
            self.assertEqual(subprocess.run(args, capture_output=True).returncode, 2)

    def test_native_multi_person_export_keeps_two_approval_accounting(self):
        value = p7b.build_plan(START, HOURS, ARGV, approval={"mode": "multi_person", "operator_user_id": None, "allowed_actions": []})
        self.assertEqual(crit(status(window(), full_measurements(), p=value), "rollback_p95"), "met")
        self.assertEqual(crit(status(window(), [solo_canary(i) for i in range(10)], p=value), "rollback_p95"), "not_measured")

    def test_designated_confirmation_counts_in_pinned_single_operator_plan(self):
        rows = full_measurements()[10:] + [solo_canary(i) for i in range(10)]
        report = status(window(), rows, p=solo_plan())
        self.assertEqual(crit(report, "rollback_p95"), "met")
        self.assertEqual(report["status"], "CRITERIA_MET_REQUIRES_OPERATOR_REVIEW")
        self.assertFalse(report["gate_passed"])

    def test_single_confirmation_never_changes_the_default_plan(self):
        self.assertEqual(crit(status(window(), [solo_canary(i) for i in range(10)]), "rollback_p95"), "not_measured")

    def test_foreign_missing_or_unbound_native_confirmation_does_not_count(self):
        mutations = [
            {"approval_evidence": {}},
            {"approval_evidence": {**solo_canary(0)["approval_evidence"], "approver_id": "00000000-0000-0000-0000-000000000088"}},
            {"approval_evidence": {**solo_canary(0)["approval_evidence"], "approval_mode": "distinct_person"}},
            {"approval_context_hash": "b" * 64},
            {"approval_context_hash": ""},
            {"approval_profile": {"mode": "multi_person"}},
            {"action": "quarantine.host"},
            {"required_approvals": 2},
            {"distinct_human_approvals": True},
            {"lab": True},
        ]
        for change in mutations:
            with self.subTest(change=change):
                rows = []
                for i in range(10):
                    row = solo_canary(i)
                    row.update(copy.deepcopy(change))
                    rows.append(row)
                self.assertEqual(crit(status(window(), rows, p=solo_plan()), "rollback_p95"), "not_measured")

    def test_duplicate_request_rows_cannot_fill_the_canary_sample_size(self):
        rows = [solo_canary(0) for _ in range(10)]
        self.assertEqual(crit(status(window(), rows, p=solo_plan()), "rollback_p95"), "not_measured")
        self.assertEqual(crit(status(window(), [canary(0)] * 10), "rollback_p95"), "not_measured")

    def test_profile_is_registered_before_window_and_cannot_be_edited(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "plan.json"
            value = solo_plan()
            path.write_text(json.dumps(value))
            p7b.load_plan(path)
            value["approval_profile"]["operator_user_id"] = "00000000-0000-0000-0000-000000000088"
            path.write_text(json.dumps(value))
            with self.assertRaises(p7b.BadInput):
                p7b.load_plan(path)

    def test_invalid_or_out_of_scope_single_operator_profile_is_rejected(self):
        for change in ({"operator_user_id": ""}, {"mode": "automatic"},
                       {"allowed_actions": []}, {"allowed_actions": ["quarantine.host"]}):
            with self.subTest(change=change):
                value = solo_plan()
                value["approval_profile"].update(change)
                with self.assertRaises(p7b.BadInput):
                    p7b.validate_plan(value)


class PlanTests(unittest.TestCase):
    def test_edited_criteria_after_registration_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "plan.json"
            value = plan(confirmed=False)
            path.write_text(json.dumps(value))
            p7b.load_plan(path)
            value["criteria"]["min_cycle_availability"] = 0.5
            path.write_text(json.dumps(value))
            with self.assertRaises(p7b.BadInput):
                p7b.load_plan(path)

    def test_confirmation_does_not_change_the_registered_hash(self):
        a = plan(confirmed=False)
        b = dict(a, operator_confirmed_by="op", operator_confirmed_at="2026-10-25T00:00:00Z")
        self.assertEqual(p7b.canonical_hash(a), p7b.canonical_hash(b))

    def test_a_probe_that_could_hide_a_gap_is_refused(self):
        with self.assertRaises(p7b.BadInput):
            p7b.build_plan(START, 48, ARGV, probe={"attempts_per_cycle": 5, "attempt_timeout_seconds": 40, "backoff_seconds": [5, 5, 5, 5]})

    def test_bounds(self):
        for hours in (0, 200):
            with self.assertRaises(p7b.BadInput):
                p7b.build_plan(START, hours, ARGV)
        with self.assertRaises(p7b.BadInput):
            p7b.build_plan(START, 48, "ssh host")  # a shell string is not accepted


class Clock:
    def __init__(self, t):
        self.t = t

    def now(self):
        return self.t

    def sleep(self, seconds):
        self.t += seconds


def run_probe(pl, outcomes, tmp, **kw):
    clock = Clock(START + 1)
    queue = list(outcomes)

    def attempt(argv, timeout):
        clock.t += 0.5
        return queue.pop(0) if queue else {"ok": True, "data": GOOD, "duration_s": 0.5}

    samples = str(pathlib.Path(tmp) / "samples.jsonl")
    code, message = p7b.probe(pl, samples, now=clock.now, sleep=clock.sleep, attempt_fn=attempt, **kw)
    return code, message, p7b.load_jsonl(samples)


FAIL = {"ok": False, "error_class": "transport", "duration_s": 0.5}
OK = {"ok": True, "data": GOOD, "duration_s": 0.5}


class ProbeTests(unittest.TestCase):
    def test_retry_inside_a_cycle_recovers_but_the_failed_attempt_stays_visible(self):
        with tempfile.TemporaryDirectory() as tmp:
            code, _, rows = run_probe(plan(), [FAIL, FAIL, OK], tmp, max_cycles=1)
            self.assertEqual(code, 0)
            self.assertTrue(rows[0]["ssh_ok"])
            self.assertEqual([a["ok"] for a in rows[0]["attempts"]], [False, False, True])
            report = status(rows, now=START + 120)
            self.assertEqual(report["accounting"]["failed_attempts"], 2)
            self.assertEqual(report["accounting"]["failed_cycles"], 0)
            self.assertEqual(report["accounting"]["failed_attempt_classes"], {"transport": 2})

    def test_all_attempts_failing_is_a_failed_cycle(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, _, rows = run_probe(plan(), [FAIL, FAIL, FAIL], tmp, max_cycles=1)
            self.assertFalse(rows[0]["ssh_ok"])
            self.assertEqual(rows[0]["issues"], ["telemetry_unavailable"])

    def test_too_many_consecutive_failed_cycles_stop_the_probe_for_the_operator(self):
        with tempfile.TemporaryDirectory() as tmp:
            code, message, rows = run_probe(plan(), [FAIL] * 30, tmp)
            self.assertEqual(code, p7b.EXIT["TELEMETRY_STOP"])
            self.assertEqual(len(rows), 4)  # limit 3 -> the 4th consecutive failure stops
            self.assertIn("consecutive", message)

    def test_a_state_violation_stops_the_probe(self):
        bad = dict(GOOD, active_elements={"blocklist": 1, "blocklist6": 0})
        with tempfile.TemporaryDirectory() as tmp:
            code, message, rows = run_probe(plan(), [{"ok": True, "data": bad, "duration_s": 0.1}], tmp)
            self.assertEqual(code, p7b.EXIT["STATE_STOP"])
            self.assertIn("unexpected_active_block", message)
            self.assertEqual(rows[0]["issues"], ["unexpected_active_block"])

    def test_invalid_output_is_a_failure_not_a_success(self):
        class Done:
            returncode = 0
            stdout = '{"api_healthy": true}'
        original = subprocess.run
        subprocess.run = lambda *a, **k: Done()
        try:
            outcome = p7b.run_attempt(["x"], 5)
        finally:
            subprocess.run = original
        self.assertEqual((outcome["ok"], outcome["error_class"]), (False, "invalid_output"))

    def test_timeout_and_nonzero_exit_are_classified(self):
        self.assertEqual(p7b.run_attempt([sys.executable, "-c", "import time; time.sleep(5)"], 0.3)["error_class"], "timeout")
        self.assertEqual(p7b.run_attempt([sys.executable, "-c", "raise SystemExit(7)"], 5)["error_class"], "transport")
        self.assertEqual(p7b.run_attempt(["/nonexistent/binary"], 5)["error_class"], "transport")
        good = json.dumps(GOOD)
        self.assertTrue(p7b.run_attempt([sys.executable, "-c", f"print({good!r})"], 5)["ok"])

    def test_stop_file_runtime_bound_and_early_start(self):
        with tempfile.TemporaryDirectory() as tmp:
            stop = pathlib.Path(tmp) / "STOP"
            stop.write_text("")
            pl = p7b.build_plan(START, HOURS, ARGV, probe={"stop_file": str(stop)})
            code, _, rows = run_probe(pl, [], tmp)
            self.assertEqual(code, p7b.EXIT["OPERATOR_STOP"])
            self.assertEqual(rows[-1]["event"], "operator_stop")
        with tempfile.TemporaryDirectory() as tmp:
            pl = p7b.build_plan(START, HOURS, ARGV, probe={"max_runtime_seconds": 200})
            code, message, rows = run_probe(pl, [], tmp)
            self.assertEqual(code, 0)
            self.assertIn("runtime bound", message)
            self.assertLessEqual(len(rows), 4)
        with tempfile.TemporaryDirectory() as tmp:
            clock = Clock(START - 3600)
            code, message = p7b.probe(plan(), str(pathlib.Path(tmp) / "s.jsonl"), now=clock.now, sleep=clock.sleep, attempt_fn=lambda a, t: OK)
            self.assertEqual(code, p7b.EXIT["BAD_INPUT"])

    def test_cadence_holds_the_interval_so_there_is_no_nominal_shortfall(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, _, rows = run_probe(plan(), [], tmp, max_cycles=5)
            stamps = [r["timestamp"] for r in rows]
            self.assertTrue(all(abs((b - a) - 60) < 1.5 for a, b in zip(stamps, stamps[1:])), stamps)


class EvaluateTests(unittest.TestCase):
    def test_legacy_shape_of_the_first_window_is_not_met(self):
        # 2676 attempts, 168 failures in 146 runs of up to 4: the observed shape of the 2026-10-18 window.
        fails, i = set(), 5
        lengths = [1] * 130 + [2] * 12 + [3] * 2 + [4] * 2
        self.assertEqual(len(lengths), 146)
        for length in lengths:
            fails.update(range(i, i + length))
            i += length + 11
        self.assertEqual(len(fails), 168)
        rows = [{"timestamp": START + 64.6 * k, "ssh_ok": k not in fails, "data": GOOD if k not in fails else {}, "issues": [] if k not in fails else ["telemetry_unavailable"]} for k in range(2676)]
        report = status(rows)
        self.assertEqual(report["status"], "CRITERIA_NOT_MET")
        self.assertIn("cycle_availability", report["not_met"])
        self.assertIn("max_consecutive_failed_cycles", report["not_met"])
        self.assertIn("window_complete_and_covered", report["not_met"])
        self.assertIs(report["gate_passed"], False)
        self.assertEqual(report["accounting"]["failed_cycles"], 168)

    def test_a_perfect_idle_window_is_still_only_insufficient_evidence(self):
        report = status(window())
        self.assertEqual(report["status"], "INSUFFICIENT_EVIDENCE")
        for name in ("rollback_p95", "lockout_protection", "drift_detection", "false_positives", "packet_effect_each_canary"):
            self.assertEqual(crit(report, name), "not_measured", name)
        for name in ("cycle_availability", "idle_state_invariants", "window_complete_and_covered"):
            self.assertEqual(crit(report, name), "met", name)
        self.assertIs(report["gate_passed"], False)

    def test_complete_evidence_reaches_review_but_never_a_passed_gate(self):
        report = status(window(), full_measurements())
        self.assertEqual(report["status"], "CRITERIA_MET_REQUIRES_OPERATOR_REVIEW")
        self.assertIs(report["gate_passed"], False)
        self.assertIs(report["requires_operator_review"], True)

    def test_an_unconfirmed_plan_cannot_reach_review(self):
        report = status(window(), full_measurements(), p=plan(confirmed=False))
        self.assertEqual(report["status"], "INSUFFICIENT_EVIDENCE")
        self.assertIn("plan_not_confirmed_by_operator", report["reasons"])

    def test_open_window_cannot_be_complete(self):
        report = status(window(n=600), now=START + 600 * 60)
        self.assertEqual(report["status"], "INSUFFICIENT_EVIDENCE")
        self.assertIn("window_still_open", report["reasons"])

    def test_rows_outside_the_window_are_ignored(self):
        rows = window() + [cycle(0, ts=START - 100), cycle(0, ts=END + 100)]
        report = status(rows, full_measurements())
        self.assertEqual(report["accounting"]["cycles"], HOURS * 60)
        self.assertIn("2_cycle_rows_outside_window_ignored", report["reasons"])

    def test_canary_controls_lab_unapproved_and_incomplete_do_not_count(self):
        rows = [canary(i, lab=True) for i in range(10)] + [canary(i, distinct_human_approvals=1) for i in range(10)] + [canary(i, rollback_seconds=None) for i in range(10)]
        report = status(window(), rows)
        self.assertEqual(crit(report, "rollback_p95"), "not_measured")
        # nine real ones are still not enough
        report = status(window(), [canary(i) for i in range(9)])
        self.assertEqual(crit(report, "rollback_p95"), "not_measured")

    def test_slow_rollback_leaked_lockout_and_blocked_legitimate_target_are_not_met(self):
        measurements = [m for m in full_measurements()]
        measurements = [canary(i, rollback_seconds=9.0) if m["type"] == "canary" and i % 2 else m for i, m in enumerate(measurements)]
        self.assertEqual(crit(status(window(), measurements), "rollback_p95"), "not_met")
        leaked = full_measurements()
        leaked[10]["refused"] = False
        self.assertEqual(crit(status(window(), leaked), "lockout_protection"), "not_met")
        fp = full_measurements() + [{"type": "false_positive_review", "label_source": "operator", "classification": "legitimate", "was_blocked": True}]
        report = status(window(), fp)
        self.assertEqual(crit(report, "false_positives"), "not_met")
        self.assertEqual(report["status"], "CRITERIA_NOT_MET")
        missed = full_measurements()
        for m in missed:
            if m["type"] == "drift_injection":
                m["detected_at"] = None
        self.assertEqual(crit(status(window(), missed), "drift_detection"), "not_met")
        bad_packet = full_measurements()
        bad_packet[0]["blocked_dropped"] = False
        self.assertEqual(crit(status(window(), bad_packet), "packet_effect_each_canary"), "not_met")

    def test_unknown_and_lab_labels_are_not_operator_evidence(self):
        rows = [m for m in full_measurements() if m["type"] != "false_positive_review"]
        rows += [{"type": "false_positive_review", "label_source": "unknown", "classification": "legitimate", "was_blocked": True}] * 6
        rows += [{"type": "false_positive_review", "label_source": "lab_controlled", "classification": "legitimate", "was_blocked": True}] * 6
        report = status(window(), rows)
        self.assertEqual(crit(report, "false_positives"), "not_measured")
        self.assertEqual(report["accounting"]["label_counts"], {"operator": 0, "lab_controlled": 6, "unknown": 6})

    def test_long_telemetry_gap_fails_even_with_high_availability(self):
        report = status(window(fail_at=range(100, 105)))  # 5 consecutive cycles = 300 s+ with 1439/1440... still > limit
        self.assertEqual(crit(report, "max_consecutive_failed_cycles"), "not_met")
        self.assertEqual(crit(report, "max_gap_between_successful_cycles"), "not_met")
        self.assertEqual(crit(report, "cycle_availability"), "met")


class CliTests(unittest.TestCase):
    def run_cli(self, *args):
        return subprocess.run([sys.executable, "-I", str(HERE / "phase7b-observe.py"), *args], capture_output=True, text=True, timeout=30)

    def test_plan_is_private_never_overwritten_and_evaluate_is_exit_2_on_bad_input(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = pathlib.Path(tmp) / "plan.json"
            args = ["plan", "--out", str(out), "--start", "2026-10-26T08:00:00Z", "--hours", "48", "--probe-argv-json", '["true"]']
            first = self.run_cli(*args)
            self.assertEqual(first.returncode, 0, first.stderr)
            self.assertEqual(out.stat().st_mode & 0o777, 0o600)
            self.assertIsNone(json.loads(first.stdout)["operator_confirmed_by"])
            self.assertEqual(self.run_cli(*args).returncode, 2)
            samples = pathlib.Path(tmp) / "s.jsonl"
            report = self.run_cli("evaluate", "--plan", str(out), "--samples", str(samples), "--now", "2026-10-26T09:00:00Z")
            self.assertEqual(report.returncode, 0, report.stderr)
            self.assertIs(json.loads(report.stdout)["gate_passed"], False)
            samples.write_text("{broken\n")
            self.assertEqual(self.run_cli("evaluate", "--plan", str(out), "--samples", str(samples)).returncode, 2)
            self.assertEqual(self.run_cli("plan", "--out", str(pathlib.Path(tmp) / "x.json"), "--start", "2026-10-26T08:00:00", "--probe-argv-json", '["true"]').returncode, 2)


if __name__ == "__main__":
    unittest.main()
