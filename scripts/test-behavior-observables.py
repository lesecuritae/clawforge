#!/usr/bin/env python3
"""Unit tests for scripts/behavior-observables.py (stdlib only)."""
import importlib.util
import pathlib
import unittest

spec = importlib.util.spec_from_file_location(
    "observables", pathlib.Path(__file__).with_name("behavior-observables.py"))
observables = importlib.util.module_from_spec(spec)
spec.loader.exec_module(observables)


def ssh(n, status=None, user="fixture"):
    events = [{"event_type": "ssh_login_failure", "username": f"{user}{i}", "dedupe_key": f"k{i}",
               "occurred_at": "t", "resource": "203.0.113.1", "severity": "medium"} for i in range(n)]
    return events


def http(n, status):
    return [{"event_type": "http_anomaly", "path": f"/p-{i}", "status_code": status,
             "dedupe_key": f"k{i}", "occurred_at": "t", "resource": "203.0.113.2"} for i in range(n)]


def case(id, attack, events):
    return {"case": {"id": id, "label_attack": attack}, "events": events}


class ObservablesTests(unittest.TestCase):
    def test_same_shapes_with_different_counts_are_indistinguishable(self):
        cases = {"legit": case("legit", False, ssh(6)), "attack": case("attack", True, ssh(5))}
        pairs = observables.compare(cases)
        self.assertEqual([(p["legitimate_case"], p["attack_case"]) for p in pairs],
                         [("legit", "attack")])
        self.assertTrue(pairs[0]["same_event_shapes"])

    def test_a_different_status_class_is_a_real_discriminator(self):
        cases = {"outage": case("outage", False, http(12, 503)),
                 "abuse": case("abuse", True, http(12, 404))}
        self.assertEqual(observables.compare(cases), [])

    def test_a_different_field_value_separates_cases(self):
        cases = {"legit": case("legit", False, ssh(6, user="alice")),
                 "attack": case("attack", True, ssh(6, user="root"))}
        self.assertEqual(observables.compare(cases), [])

    def test_only_alerting_legitimate_cases_are_compared(self):
        cases = {"quiet": case("quiet", False, ssh(1)), "loud": case("loud", False, ssh(6)),
                 "attack": case("attack", True, ssh(5))}
        pairs = observables.compare(cases, alerting={"loud"})
        self.assertEqual([p["legitimate_case"] for p in pairs], ["loud"])

    def test_identifiers_that_cannot_carry_intent_are_ignored(self):
        a = ssh(2)
        b = ssh(2)
        for event in b:
            event["resource"] = "203.0.113.99"
            event["dedupe_key"] = "other"
            event["occurred_at"] = "later"
        self.assertEqual({observables.shape(e) for e in a}, {observables.shape(e) for e in b})


if __name__ == "__main__":
    unittest.main()
