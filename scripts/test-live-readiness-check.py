#!/usr/bin/env python3
"""Tests for scripts/live-readiness-check.py (stdlib only). Synthetic states: they prove the checklist's
boundaries and the invariant that it never declares readiness, not anything about production."""
import copy
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
spec = importlib.util.spec_from_file_location("lr", HERE / "live-readiness-check.py")
lr = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lr)
NOW = dt.datetime(2026, 10, 24, 13, 0, tzinfo=dt.timezone.utc)

GOOD = {
    "executor_env": {"CLAWFORGE_EXECUTOR_DRY_RUN": "true", "CLAWFORGE_EXECUTOR_LIVE_AUTHORIZATION": "",
                     "CLAWFORGE_FIREWALL_NEVER_BLOCK_CIDRS": "192.168.0.0/24,100.64.0.0/10",
                     "CLAWFORGE_FIREWALL_MAX_TTL_SECONDS": "900", "CLAWFORGE_FIREWALL_MAX_APPLIES_PER_WINDOW": "2",
                     "CLAWFORGE_FIREWALL_RATE_WINDOW_SECONDS": "300", "CLAWFORGE_FIREWALL_MAX_CONCURRENT_APPLIES_PER_ADAPTER": "5"},
    "policy_engine_env": {"CLAWFORGE_POLICY_BRIDGE_MODE": ""},
    "worker_env": {"CLAWFORGE_ENABLE_IP_CONTEXT": ""},
    "actions": [{"name": "nftables.block_incident_source", "enabled": False}],
    "policies": [{"name": "p", "class": "observe", "status": "active"}],
    "runtime": [{"component": c, "state": "running", "heartbeat_age_seconds": 5}
                for c in ("policy-engine", "security-engine", "executor", "worker", "correlation", "api", "incidents")],
    "sensors": [{"name": "a", "age_seconds": 10}],
    "providers": [{"id": f, "enabled": True, "interval_seconds": 3600, "state": "ok", "last_success_age_seconds": 100} for f in lr.COUNTING_FEEDS],
    "orphan_security_definer_functions": [],
    "backup": {"files": 1, "newest_age_seconds": 3600, "newest_bytes": 24 * 2**30, "free_gib": 400, "retention_days": 14},
    "shape_verdict": {"status": "OBSERVED"},
    "restore_receipt": {"kind": "clawforge-restore-drill", "isolated": True, "dump_name": "d.dump", "dump_created_at": "2026-10-23T00:55:31Z",
                        "verified_at": "2026-10-24T06:00:00Z", "pg_restore_exit": 0, "tables_expected": 87, "tables_restored": 87,
                        "invalid_indexes": 0, "unvalidated_constraints": 0, "big_tables_with_rows": True, "migrator_current": True},
}


def state(**changes):
    s = copy.deepcopy(GOOD)
    for key, value in changes.items():
        if isinstance(value, dict) and isinstance(s.get(key), dict):
            s[key].update(value)
        else:
            s[key] = value
    return s


def by_id(report):
    return {i["id"]: i["status"] for i in report["gates_closed"] + report["prerequisites"]}


class Invariants(unittest.TestCase):
    def test_a_state_where_every_check_passes_is_still_not_live_ready(self):
        report = lr.evaluate(state(), NOW)
        self.assertTrue(all(s == "PASS" for s in by_id(report).values()), by_id(report))
        self.assertIs(report["live_ready"], False)
        self.assertEqual(report["summary"], {"gates_open_or_unknown": [], "prerequisites_failing": [], "prerequisites_unknown": []})
        self.assertGreaterEqual(len(report["outstanding_human_items"]), 5)
        text = " ".join(report["outstanding_human_items"]).lower()
        for needle in ("two independent", "labelled", "phase 7b", "reboot", "protection values"):
            self.assertIn(needle, text)

    def test_the_source_has_no_path_that_sets_live_ready_true(self):
        source = (HERE / "live-readiness-check.py").read_text()
        self.assertNotIn('"live_ready": True', source)
        self.assertNotIn("live_ready=True", source)


class Gates(unittest.TestCase):
    def test_each_opened_gate_is_a_fail(self):
        cases = {
            "executor_dry_run": state(executor_env={"CLAWFORGE_EXECUTOR_DRY_RUN": "false"}),
            "no_live_authorization": state(executor_env={"CLAWFORGE_EXECUTOR_LIVE_AUTHORIZATION": '{"version":1}'}),
            "bridge_off": state(policy_engine_env={"CLAWFORGE_POLICY_BRIDGE_MODE": "simulate"}),
            "all_actions_disabled": state(actions=[{"name": "nftables.block_incident_source", "enabled": True}]),
            "active_policies_observe_only": state(policies=[{"name": "p", "class": "automatic", "status": "active"}]),
            "ripestat_enrichment_unchanged_off": state(worker_env={"CLAWFORGE_ENABLE_IP_CONTEXT": "true"}),
        }
        for gate, s in cases.items():
            with self.subTest(gate=gate):
                report = lr.evaluate(s, NOW)
                self.assertEqual(by_id(report)[gate], "FAIL")
                self.assertIn(gate, report["summary"]["gates_open_or_unknown"])
                self.assertIs(report["live_ready"], False)

    def test_an_inactive_non_observe_policy_does_not_open_the_gate_and_missing_data_is_unknown(self):
        report = lr.evaluate(state(policies=[{"name": "p", "class": "automatic", "status": "draft"}]), NOW)
        self.assertEqual(by_id(report)["active_policies_observe_only"], "PASS")
        report = lr.evaluate(state(actions=[], policies=[]), NOW)
        self.assertEqual(by_id(report)["all_actions_disabled"], "UNKNOWN")
        self.assertEqual(by_id(report)["active_policies_observe_only"], "UNKNOWN")


class Prerequisites(unittest.TestCase):
    def status(self, item_id, **changes):
        return by_id(lr.evaluate(state(**changes), NOW))[item_id]

    def test_never_block_needs_a_real_entry(self):
        for value in ("", " ", ",", " , "):
            self.assertEqual(self.status("never_block_list_defined", executor_env={"CLAWFORGE_FIREWALL_NEVER_BLOCK_CIDRS": value}), "FAIL", value)
        self.assertEqual(self.status("never_block_list_defined", executor_env={"CLAWFORGE_FIREWALL_NEVER_BLOCK_CIDRS": "10.0.0.1"}), "PASS")

    def test_pilot_limit_boundaries(self):
        ttl = lambda v: self.status("ttl_ceiling_at_pilot_limit", executor_env={"CLAWFORGE_FIREWALL_MAX_TTL_SECONDS": v})
        self.assertEqual((ttl("900"), ttl("899"), ttl("901"), ttl(""), ttl("abc")), ("PASS", "PASS", "FAIL", "FAIL", "FAIL"))
        applies = lambda v, w="300": self.status("apply_budget_at_pilot_limit", executor_env={"CLAWFORGE_FIREWALL_MAX_APPLIES_PER_WINDOW": v, "CLAWFORGE_FIREWALL_RATE_WINDOW_SECONDS": w})
        self.assertEqual((applies("2"), applies("1"), applies("3"), applies("20"), applies("2", "60")), ("PASS", "PASS", "FAIL", "FAIL", "FAIL"))
        conc = lambda v: self.status("concurrency_budget_explicit", executor_env={"CLAWFORGE_FIREWALL_MAX_CONCURRENT_APPLIES_PER_ADAPTER": v})
        self.assertEqual((conc("5"), conc("6"), conc("")), ("PASS", "FAIL", "FAIL"))

    def test_runtime_heartbeat_state_and_age(self):
        def with_runtime(**kw):
            rows = copy.deepcopy(GOOD["runtime"])
            rows[0].update(kw)
            return self.status("runtime_policy-engine", runtime=rows)
        self.assertEqual(with_runtime(heartbeat_age_seconds=120), "PASS")
        self.assertEqual(with_runtime(heartbeat_age_seconds=121), "FAIL")
        self.assertEqual(with_runtime(state="degraded"), "FAIL")
        self.assertEqual(with_runtime(heartbeat_age_seconds=None), "FAIL")
        self.assertEqual(self.status("runtime_executor", runtime=[]), "UNKNOWN")

    def test_sensors_orphans_and_feeds(self):
        self.assertEqual(self.status("all_sensors_fresh", sensors=[{"name": "a", "age_seconds": 301}]), "FAIL")
        self.assertEqual(self.status("all_sensors_fresh", sensors=[{"name": "a", "age_seconds": None}]), "FAIL")
        self.assertEqual(self.status("all_sensors_fresh", sensors=[]), "UNKNOWN")
        self.assertEqual(self.status("no_orphaned_security_definer_functions", orphan_security_definer_functions=["clawforge_x"]), "FAIL")
        self.assertEqual(self.status("no_orphaned_security_definer_functions", orphan_security_definer_functions=None), "UNKNOWN")
        stale = [{"id": f, "enabled": True, "interval_seconds": 3600, "state": "ok", "last_success_age_seconds": 7201} for f in lr.COUNTING_FEEDS]
        self.assertEqual(self.status("feed_spamhaus_drop", providers=stale), "FAIL")
        errored = [dict(p, state="error") for p in GOOD["providers"]]
        self.assertEqual(self.status("feed_feodo_tracker", providers=errored), "FAIL")
        self.assertEqual(self.status("feed_feodo_tracker", providers=[]), "UNKNOWN")

    def test_failing_non_counting_feeds_are_a_warning_not_a_blocker(self):
        providers = GOOD["providers"] + [{"id": "threatfox", "enabled": True, "interval_seconds": 900, "state": "error", "last_success_age_seconds": None}]
        report = lr.evaluate(state(providers=providers), NOW)
        self.assertTrue(any("threatfox" in w for w in report["warnings"]))
        self.assertEqual(report["summary"]["prerequisites_failing"], [])

    def test_bridge_evidence_age_must_cover_the_feed_cadence_once_a_mode_is_chosen(self):
        env = lambda mode, age: {"CLAWFORGE_POLICY_BRIDGE_MODE": mode, "CLAWFORGE_POLICY_BRIDGE_MAX_EVIDENCE_AGE_SECONDS": age}
        check = lambda mode, age: self.status("bridge_evidence_age_covers_feed_cadence", policy_engine_env=env(mode, age))
        # GOOD providers use a 3600 s interval, so 2x = 7200 s
        self.assertEqual(check("", ""), "PASS")  # bridge off: not applicable
        self.assertEqual(check("propose", "7200"), "PASS")
        self.assertEqual(check("propose", "900"), "FAIL")
        self.assertEqual(check("simulate", "3600"), "FAIL")
        self.assertEqual(check("automatic", "604800"), "PASS")
        self.assertEqual(check("propose", ""), "UNKNOWN")
        self.assertEqual(check("propose", "abc"), "UNKNOWN")

    def test_single_operator_profile_is_reported_honestly_and_changes_only_the_human_step_wording(self):
        base = lr.evaluate(state(), NOW)
        self.assertEqual(by_id(base)["approval_profile"], "PASS")
        self.assertIn("two independent", base["outstanding_human_items"][0])
        single = lr.evaluate(state(approval_profile={"mode": "single_operator", "allowed_actions": ["nftables.block_incident_source"], "operator_enabled": True}), NOW)
        self.assertEqual(by_id(single)["approval_profile"], "PASS")
        self.assertIn("one explicit", single["outstanding_human_items"][0])
        self.assertIn("cannot be created by an agent", single["outstanding_human_items"][0])
        self.assertIs(single["live_ready"], False)
        # all other human items stay, the gates are not touched
        self.assertEqual(single["outstanding_human_items"][1:], base["outstanding_human_items"][1:])
        self.assertEqual([g["status"] for g in single["gates_closed"]], [g["status"] for g in base["gates_closed"]])
        broken = lr.evaluate(state(approval_profile={"mode": "single_operator", "allowed_actions": [], "operator_enabled": False}), NOW)
        self.assertEqual(by_id(broken)["approval_profile"], "FAIL")

    def test_abuse_ch_failures_are_informational_and_never_a_blocker(self):
        providers = GOOD["providers"] + [{"id": "threatfox", "enabled": True, "interval_seconds": 900, "state": "error", "last_success_age_seconds": None}]
        report = lr.evaluate(state(providers=providers), NOW)
        self.assertTrue(any("OPTIONAL" in w for w in report["warnings"]))
        self.assertEqual(report["summary"]["prerequisites_failing"], [])

    def test_backup_is_never_assumed(self):
        self.assertEqual(self.status("recent_restorable_backup", backup=None), "UNKNOWN")
        self.assertEqual(self.status("recent_restorable_backup", backup={"files": 0, "newest_age_seconds": None, "newest_bytes": None, "free_gib": 100}), "FAIL")
        self.assertEqual(self.status("recent_restorable_backup", backup={"files": 1, "newest_age_seconds": 200000, "newest_bytes": 24 * 2**30, "free_gib": 400}), "FAIL")
        self.assertEqual(self.status("recent_restorable_backup", backup={"files": 1, "newest_age_seconds": 100, "newest_bytes": 1000, "free_gib": 400}), "FAIL")
        report = lr.evaluate(state(backup={"free_gib": 160}), NOW)
        self.assertTrue(any("exceeds" in w for w in report["warnings"]), report["warnings"])

    def test_restore_drill_receipt_is_separate_evidence_and_never_upgrades_the_backup_item(self):
        good = {"kind": "clawforge-restore-drill", "isolated": True, "dump_name": "d.dump", "dump_created_at": "2026-10-24T00:55:31Z",
                "verified_at": "2026-10-26T04:35:00Z", "pg_restore_exit": 0, "tables_expected": 87, "tables_restored": 87,
                "invalid_indexes": 0, "unvalidated_constraints": 0, "big_tables_with_rows": True, "migrator_current": True}
        now = dt.datetime(2026, 10, 27, tzinfo=dt.timezone.utc)
        def run(receipt, **kw):
            s = state(**kw)
            s["restore_receipt"] = receipt  # replaced, not merged: state() merges dicts and would refill a missing field
            return by_id(lr.evaluate(s, now))
        self.assertEqual(run(None)["restore_drill_verified"], "UNKNOWN")
        self.assertEqual(run(good)["restore_drill_verified"], "PASS")
        # the existence/age item is judged only on the dump files: an unreadable volume stays UNKNOWN even with a receipt
        self.assertEqual(run(good, backup=None)["recent_restorable_backup"], "UNKNOWN")
        bad_cases = {
            "exit": dict(good, pg_restore_exit=1), "tables": dict(good, tables_restored=86), "indexes": dict(good, invalid_indexes=2),
            "constraints": dict(good, unvalidated_constraints=1), "big tables": dict(good, big_tables_with_rows=False),
            "migrator": dict(good, migrator_current=False), "kind": dict(good, kind="other"), "not isolated": dict(good, isolated=False),
            "stale drill": dict(good, verified_at="2026-08-01T00:00:00Z", dump_created_at="2026-07-31T00:00:00Z"),
            "old dump": dict(good, dump_created_at="2026-10-01T00:00:00Z"), "future": dict(good, verified_at="2026-12-01T00:00:00Z"),
            "missing field": {k: v for k, v in good.items() if k != "verified_at"}, "zero tables": dict(good, tables_expected=0, tables_restored=0)}
        for name, receipt in bad_cases.items():
            self.assertEqual(run(receipt)["restore_drill_verified"], "FAIL", name)

    def test_shape_observation_follows_the_evaluator_verdict(self):
        self.assertEqual(self.status("shape_observation_24h", shape_verdict=None), "UNKNOWN")
        for verdict in ("INSUFFICIENT_DATA", "TOO_EARLY", "REHEARSAL"):
            self.assertEqual(self.status("shape_observation_24h", shape_verdict={"status": verdict}), "FAIL", verdict)


class CommandLine(unittest.TestCase):
    def test_fixture_run_and_private_output_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            fixture = pathlib.Path(tmp) / "state.json"
            fixture.write_text(json.dumps(GOOD))
            out = pathlib.Path(tmp) / "report.json"
            result = subprocess.run([sys.executable, "-I", str(HERE / "live-readiness-check.py"), "--collected-fixture", str(fixture), "--out", str(out)],
                                    capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIs(json.loads(result.stdout)["live_ready"], False)
            self.assertEqual(out.stat().st_mode & 0o777, 0o600)
            broken = pathlib.Path(tmp) / "broken.json"
            broken.write_text("{not json")
            bad = subprocess.run([sys.executable, "-I", str(HERE / "live-readiness-check.py"), "--collected-fixture", str(broken)], capture_output=True, text=True, timeout=30)
            self.assertEqual(bad.returncode, 2)
            self.assertIs(json.loads(bad.stdout)["live_ready"], False)


if __name__ == "__main__":
    unittest.main()
