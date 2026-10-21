#!/usr/bin/env python3
"""Unit tests for scripts/pilot-observation-evaluate.py (stdlib only)."""
import importlib.util
import json
import os
import pathlib
import tempfile
import unittest

spec = importlib.util.spec_from_file_location(
    "evaluate", pathlib.Path(__file__).with_name("pilot-observation-evaluate.py"))
evaluate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(evaluate)

IDLE = {"unresolved_generations": 0, "executable_requests": 0,
        "active_elements": {"blocklist": 0, "blocklist6": 0},
        "running_executors": [], "api_healthy": True}


def sample(ts, ok=True, data=None, issues=None):
    return {"timestamp": ts, "ssh_ok": ok, "data": (data or IDLE) if ok else {},
            "issues": issues if issues is not None else ([] if ok else ["telemetry_unavailable"])}


class Fixture:
    def __init__(self, rows, interval=60, window=600):
        self.dir = tempfile.TemporaryDirectory()
        base = pathlib.Path(self.dir.name)
        self.samples = base / "samples.jsonl"
        self.config = base / "config.json"
        self.samples.write_text("".join(json.dumps(r) + "\n" for r in rows))
        self.config.write_text(json.dumps({"started_at": 1000.0, "ends_at": 1000.0 + window,
                                           "interval_seconds": interval}))

    def run(self):
        started, ends, interval = evaluate.load_config(self.config)
        return evaluate.evaluate(evaluate.load_samples(self.samples), started, ends, interval)


def rows(n, start=1005.0, step=60.0, failed=()):
    return [sample(start + i * step, ok=i not in failed) for i in range(n)]


class EvaluatorTests(unittest.TestCase):
    def test_failed_probes_are_attempts_not_missing_rows(self):
        report = Fixture(rows(10, failed={2, 3, 7})).run()
        sampling = report["sampling"]
        self.assertEqual(sampling["recorded_attempts"], 10)
        self.assertEqual(sampling["failed_probes"], 3)
        self.assertEqual(sampling["successful_probes"], 7)
        self.assertEqual(sampling["failure_runs"], 2)
        self.assertEqual(sampling["longest_failure_run_attempts"], 2)
        self.assertEqual(sampling["nominal_expected_samples"], 10)
        self.assertEqual(sampling["largest_gap_between_successful_probes_seconds"], 180.0)

    def test_a_perfect_idle_run_still_cannot_pass_a_gate(self):
        report = Fixture(rows(10, start=1001.0)).run()
        self.assertTrue(report["state"]["invariants_hold"])
        gate = report["gate"]
        self.assertFalse(gate["automatic_rule_gate_passed"])
        self.assertTrue(gate["requires_operator_review"])
        for name in ("false_positive_rate", "rollback_latency_p95", "lockout_slo",
                     "drift_detection_time"):
            self.assertIn(name, report["not_measured"])
            self.assertIn(f"{name}_not_measured", gate["blockers"])
        self.assertNotIn("telemetry_failures_present", gate["blockers"])

    def test_telemetry_failures_and_gaps_are_blockers(self):
        report = Fixture(rows(10, failed={4})).run()
        self.assertIn("telemetry_failures_present", report["gate"]["blockers"])
        gappy = rows(10)
        del gappy[4:7]
        report = Fixture(gappy).run()
        self.assertEqual(report["sampling"]["gaps_over_limit"], 1)
        self.assertIn("observation_gap_over_limit", report["gate"]["blockers"])

    def test_window_edges_count_as_gaps(self):
        late_start = Fixture(rows(5, start=1500.0)).run()
        self.assertIn("observation_gap_over_limit", late_start["gate"]["blockers"])
        early_end = Fixture(rows(4, start=1001.0)).run()
        self.assertIn("observation_gap_over_limit", early_end["gate"]["blockers"])

    def test_state_violations_are_reported_and_block(self):
        bad = dict(IDLE, unresolved_generations=2, running_executors=["x"],
                   active_elements={"blocklist": 1, "blocklist6": 0}, api_healthy=False)
        data = rows(10)
        data[5] = sample(1005.0 + 5 * 60.0, data=bad, issues=["unexpected_active_block"])
        report = Fixture(data).run()
        state = report["state"]
        self.assertFalse(state["invariants_hold"])
        self.assertEqual(state["unresolved_generations_peak"], 2)
        self.assertEqual(state["active_block_elements_peak"], 1)
        self.assertEqual(state["samples_with_running_executor"], 1)
        self.assertEqual(state["samples_with_unhealthy_api"], 1)
        self.assertIn("state_invariant_violated_or_unobserved", report["gate"]["blockers"])

    def test_all_probes_failed_is_not_reported_as_idle(self):
        report = Fixture(rows(5, failed={0, 1, 2, 3, 4})).run()
        self.assertFalse(report["state"]["invariants_hold"])
        self.assertIsNone(report["sampling"]["largest_gap_between_successful_probes_seconds"])

    def test_malformed_input_fails_closed(self):
        for content in ["not json\n", json.dumps({"timestamp": 1}) + "\n",
                        json.dumps({"timestamp": 1, "ssh_ok": "yes"}) + "\n", ""]:
            fixture = Fixture([])
            fixture.samples.write_text(content)
            with self.assertRaises(evaluate.InvalidInput):
                evaluate.load_samples(fixture.samples)
        backwards = Fixture([sample(2000.0), sample(1900.0)])
        with self.assertRaises(evaluate.InvalidInput):
            evaluate.load_samples(backwards.samples)
        bad_config = Fixture(rows(1))
        bad_config.config.write_text(json.dumps({"started_at": 5, "ends_at": 1, "interval_seconds": 60}))
        with self.assertRaises(evaluate.InvalidInput):
            evaluate.load_config(bad_config.config)

    def test_cli_exit_status_and_deterministic_output(self):
        fixture = Fixture(rows(10))
        args = ["--samples", str(fixture.samples), "--config", str(fixture.config)]
        self.assertEqual(evaluate.main(args), 0)
        self.assertEqual(evaluate.main(["--samples", str(fixture.dir.name + "/missing"),
                                        "--config", str(fixture.config)]), 2)


if __name__ == "__main__":
    unittest.main()
