#!/usr/bin/env python3
"""Unit and isolated acceptance tests for scripts/shape-observation-evaluate.py (stdlib only).

The reader result here is synthetic and labelled so: these tests prove the evaluator's refusals and
invariants, not anything about real traffic."""
import datetime as dt
import importlib.util
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

HERE = pathlib.Path(__file__).parent
spec = importlib.util.spec_from_file_location("shape_eval", HERE / "shape-observation-evaluate.py")
shape = importlib.util.module_from_spec(spec)
spec.loader.exec_module(shape)

START = dt.datetime(2026, 10, 23, 12, 50, tzinfo=dt.timezone.utc)
END = START + dt.timedelta(hours=24)
AFTER = END + dt.timedelta(minutes=1)


def complete(**changes):
    """A synthetic reader result in which every completeness check passes."""
    hours = []
    t = dt.datetime(2026, 10, 23, 13, 0, tzinfo=dt.timezone.utc)
    while t + dt.timedelta(hours=1) <= END:
        hours.append({"hour": t.isoformat(), "ssh_events": 200, "assessments": 10, "decisions": 10})
        t += dt.timedelta(hours=1)
    data = {
        "full_hours": hours,
        "ssh_events": {"total": 4800, "with_verdict": 4800, "invalid_user": 2400},
        "ssh_decisions": {"total": 240, "with_attack_shape_snapshot": 240},
        "decisions_by_shape_basis": [{"shape_kind": "none", "basis": "behavior_only", "decision": "challenge", "corroborated": False, "count": 100}],
        "invalid_account_probe": {"decisions": 3, "sources": 2, "min_invalid": 4, "max_invalid": 6, "newly_corroborated": 2},
        "assessments_in_window": 240,
        "undecided_assessments_with_active_policy": 0,
        "delivery_backlog_security_engine": 0,
        "policy_engine": {"state": "running", "heartbeat_age_seconds": 5},
        "ssh_sensor_age_seconds": 12,
        "schema_version": 69,
    }
    data.update(changes)
    return data


def run(data, now=AFTER, hours=24, rehearsal=False):
    return shape.evaluate(data, now, START, hours, rehearsal)


def failed(verdict):
    return {c["name"] for c in verdict["checks"] if not c["ok"]}


class Refusals(unittest.TestCase):
    def test_too_early_refuses_and_needs_no_data(self):
        for now in (START, END - dt.timedelta(seconds=1), END - dt.timedelta(hours=11)):
            verdict = run(None, now=now)
            self.assertEqual(verdict["status"], "TOO_EARLY")
            self.assertIsNone(verdict["measurements"])
            self.assertEqual(failed(verdict), {"window_closed"})

    def test_the_exact_close_instant_is_allowed(self):
        self.assertEqual(run(complete(), now=END)["status"], "OBSERVED")

    def test_no_data_is_insufficient(self):
        self.assertEqual(run(None)["status"], "INSUFFICIENT_DATA")

    def test_a_window_shorter_than_24_hours_is_never_observed(self):
        verdict = shape.evaluate(complete(), AFTER, START, 12)
        self.assertEqual(verdict["status"], "INSUFFICIENT_DATA")
        self.assertIn("window_at_least_24h", failed(verdict))

    def test_each_completeness_failure_is_named_and_refuses(self):
        cases = {
            "ssh_events_every_full_hour": lambda: complete(full_hours=[dict(h, ssh_events=0) if i == 5 else h for i, h in enumerate(complete()["full_hours"])]),
            "decisions_every_hour_with_assessments": lambda: complete(full_hours=[dict(h, decisions=0) if i == 7 else h for i, h in enumerate(complete()["full_hours"])]),
            "full_hours_present": lambda: complete(full_hours=complete()["full_hours"][:10]),
            "verdict_coverage": lambda: complete(ssh_events={"total": 4800, "with_verdict": 4000, "invalid_user": 100}),
            "attack_shape_in_decision_snapshots": lambda: complete(ssh_decisions={"total": 240, "with_attack_shape_snapshot": 100}),
            "no_undecided_assessments": lambda: complete(undecided_assessments_with_active_policy=167),
            "no_delivery_backlog_for_the_window": lambda: complete(delivery_backlog_security_engine=3),
            "policy_engine_running_and_fresh": lambda: complete(policy_engine={"state": "degraded", "heartbeat_age_seconds": 5}),
            "ssh_sensor_fresh": lambda: complete(ssh_sensor_age_seconds=2257),
        }
        for name, build in cases.items():
            with self.subTest(check=name):
                verdict = run(build())
                self.assertEqual(verdict["status"], "INSUFFICIENT_DATA")
                self.assertIn(name, failed(verdict))

    def test_missing_sections_are_missing_data_not_a_pass(self):
        for key in ("full_hours", "ssh_events", "ssh_decisions", "undecided_assessments_with_active_policy",
                    "delivery_backlog_security_engine", "policy_engine", "ssh_sensor_age_seconds"):
            with self.subTest(missing=key):
                data = complete()
                del data[key]
                self.assertEqual(run(data)["status"], "INSUFFICIENT_DATA")
                data[key] = None
                self.assertEqual(run(data)["status"], "INSUFFICIENT_DATA")

    def test_a_stale_policy_heartbeat_or_missing_sensor_refuses(self):
        self.assertEqual(run(complete(policy_engine={"state": "running", "heartbeat_age_seconds": 900}))["status"], "INSUFFICIENT_DATA")
        self.assertEqual(run(complete(policy_engine={"state": "running"}))["status"], "INSUFFICIENT_DATA")


class NeverPasses(unittest.TestCase):
    def assert_gate_closed(self, verdict):
        self.assertIs(verdict["operator_gate_passed"], False)
        self.assertIsNone(verdict["quality_gate_verdict"])
        self.assertIs(verdict["requires_operator_review"], True)
        self.assertIs(verdict["labels_available"], False)

    def test_every_status_keeps_the_gate_closed(self):
        for verdict in (run(None, now=START), run(None), run(complete()), run(complete(), now=START, rehearsal=True),
                        run(complete(undecided_assessments_with_active_policy=1))):
            self.assert_gate_closed(verdict)

    def test_a_fully_observed_window_is_still_only_measurements(self):
        verdict = run(complete())
        self.assertEqual(verdict["status"], "OBSERVED")
        self.assert_gate_closed(verdict)
        self.assertEqual(failed(verdict), set())
        self.assertIn("false_positive_rate", verdict["not_measured"])
        self.assertIn("gate_7b", verdict["not_measured"])
        self.assertNotIn("pass", json.dumps(verdict).lower().replace("operator_gate_passed", ""))

    def test_rehearsal_is_never_observed_even_with_complete_data(self):
        verdict = run(complete(), now=START, rehearsal=True)
        self.assertEqual(verdict["status"], "REHEARSAL")
        self.assertIn("window_closed", failed(verdict))

    def test_no_code_path_can_set_the_gate_true(self):
        source = (HERE / "shape-observation-evaluate.py").read_text()
        self.assertNotIn('"operator_gate_passed": True', source)
        self.assertNotIn("operator_gate_passed=True", source)
        self.assertNotIn("quality_gate_verdict=", source.replace('"quality_gate_verdict": None', ""))


class CommandLine(unittest.TestCase):
    def cli(self, *args, fixture=None):
        argv = [sys.executable, "-I", str(HERE / "shape-observation-evaluate.py"), *args]
        if fixture is not None:
            with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as handle:
                json.dump(fixture, handle)
            argv += ["--reader-fixture", handle.name]
        try:
            return subprocess.run(argv, capture_output=True, text=True, timeout=30)
        finally:
            if fixture is not None:
                os.unlink(handle.name)

    def test_exit_codes_and_machine_readable_output(self):
        early = self.cli("--now", "2026-10-24T12:49:59Z", fixture=complete())
        self.assertEqual(early.returncode, 75)
        self.assertEqual(json.loads(early.stdout)["status"], "TOO_EARLY")
        ok = self.cli("--now", "2026-10-24T12:51:00Z", fixture=complete())
        self.assertEqual(ok.returncode, 0)
        document = json.loads(ok.stdout)
        self.assertEqual((document["schema"], document["status"]), ("clawforge.shape-observation/1", "OBSERVED"))
        short = self.cli("--now", "2026-10-24T12:51:00Z", fixture=complete(undecided_assessments_with_active_policy=2))
        self.assertEqual(short.returncode, 3)

    def test_too_early_never_reads_the_reader(self):
        # a fixture path that does not exist would fail closed (exit 2) if it were opened
        result = self.cli("--now", "2026-10-24T12:00:00Z", "--reader-fixture", "/nonexistent/reader.json")
        self.assertEqual(result.returncode, 75)

    def test_malformed_input_fails_closed_with_exit_2(self):
        for args in (("--window-start", "yesterday"), ("--window-start", "2026-10-23T12:50:00"), ("--hours", "0"), ("--now", "x")):
            with self.subTest(args=args):
                result = self.cli(*args)
                self.assertEqual(result.returncode, 2)
                self.assertEqual(json.loads(result.stdout)["status"], "ERROR")
                self.assertIs(json.loads(result.stdout)["operator_gate_passed"], False)
        bad = self.cli("--now", "2026-10-24T12:51:00Z", "--reader-fixture", "/nonexistent/reader.json")
        self.assertEqual(bad.returncode, 2)

    def test_output_file_is_private(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = pathlib.Path(tmp) / "verdict.json"
            self.cli("--now", "2026-10-24T12:51:00Z", "--out", str(out), fixture=complete())
            self.assertEqual(out.stat().st_mode & 0o777, 0o600)
            self.assertEqual(json.loads(out.read_text())["status"], "OBSERVED")


if __name__ == "__main__":
    unittest.main()
