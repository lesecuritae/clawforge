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


def ssh_users(names):
    return [{"event_type": "ssh_login_failure", "username": n, "dedupe_key": f"k{i}",
             "occurred_at": "t", "resource": "203.0.113.1", "severity": "medium"} for i, n in enumerate(names)]


def ssh_verdicts(logins):
    """(name, invalid) pairs: invalid is sshd's own verdict on the account (None = not reported)."""
    out = []
    for i, (n, invalid) in enumerate(logins):
        event = {"event_type": "ssh_login_failure", "username": n, "dedupe_key": f"k{i}",
                 "occurred_at": "t", "resource": "203.0.113.1", "severity": "medium"}
        if invalid is not None:
            event["invalid_user"] = invalid
        out.append(event)
    return out


def http_paths(paths):
    return [{"event_type": "http_anomaly", "path": p, "status_code": 404,
             "dedupe_key": f"k{i}", "occurred_at": "t", "resource": "203.0.113.2"} for i, p in enumerate(paths)]


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

    def test_a_different_account_name_alone_does_not_separate_cases(self):
        # Whether "alice" is a legitimate account and "root" is not cannot be known from the event.
        cases = {"legit": case("legit", False, ssh_users(["alice"] * 6)),
                 "attack": case("attack", True, ssh_users(["root"] * 6))}
        self.assertEqual(len(observables.compare(cases)), 1)

    def test_sshd_saying_the_accounts_do_not_exist_separates_a_short_dictionary_from_a_typo(self):
        typo = ssh_verdicts([("alice", False), ("alise", True)] * 3)
        dictionary = ssh_verdicts([(n, n != "root") for n in ["root", "admin", "test", "oracle", "ubuntu", "root"]])
        self.assertEqual(observables.behaviour(typo)["distinct_invalid_usernames"], 1)
        self.assertFalse(observables.behaviour(typo)["invalid_account_probe"])
        self.assertTrue(observables.behaviour(dictionary)["invalid_account_probe"])
        cases = {"typo": case("typo", False, typo), "dictionary": case("dictionary", True, dictionary)}
        self.assertEqual(observables.compare(cases), [])

    def test_a_sensor_that_does_not_report_the_verdict_never_counts_as_invalid(self):
        unknown = ssh_verdicts([(n, None) for n in ["root", "admin", "test", "oracle", "ubuntu"]])
        self.assertEqual(observables.behaviour(unknown)["distinct_invalid_usernames"], 0)

    def test_many_different_account_names_separate_enumeration_from_a_nat(self):
        nat = ssh_users(["alice", "bob", "carol"] * 4)
        walk = ssh_users([f"name{i}" for i in range(12)])
        cases = {"nat": case("nat", False, nat), "walk": case("walk", True, walk)}
        self.assertEqual(observables.compare(cases), [])
        self.assertTrue(observables.behaviour(walk)["account_enumeration"])
        self.assertFalse(observables.behaviour(nat)["account_enumeration"])

    def test_secret_file_probes_separate_a_scanner_from_missing_assets(self):
        assets = http_paths([f"/static/app.{i}.js" for i in range(10)])
        probes = http_paths(["/.env", "/.git/config", "/.aws/credentials"] + [f"/static/a{i}.js" for i in range(7)])
        cases = {"assets": case("assets", False, assets), "scan": case("scan", True, probes)}
        self.assertEqual(observables.compare(cases), [])
        self.assertEqual(observables.behaviour(probes)["signature_paths"], 3)
        # ordinary well-known files are not secret probes
        benign = http_paths(["/robots.txt", "/.well-known/security.txt", "/favicon.ico"])
        self.assertEqual(observables.behaviour(benign)["signature_paths"], 0)

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
