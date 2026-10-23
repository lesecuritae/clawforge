#!/usr/bin/env python3
"""Read-only evaluator for the 24 h attack-shape observation window (sshd invalid-user verdict, shapes).

It MEASURES and checks that the observation is complete enough to be read. It can never pass a gate:
``operator_gate_passed`` is always ``false``, ``quality_gate_verdict`` always ``null`` and
``requires_operator_review`` always ``true``. Nothing here is a formal Phase 7B result.

Refusals (no production query is executed for the first one):
  TOO_EARLY          the window [start, start + hours) has not closed yet            exit 75
  INSUFFICIENT_DATA  a completeness check failed (gap, missing verdict, backlog, ...)  exit 3
  REHEARSAL          --rehearsal skipped the clock guard to prove the reader works     exit 4
  OBSERVED           every completeness check passed; numbers are measurements only    exit 0
Malformed input or an unreadable reader result fails closed with exit 2.

    shape-observation-evaluate.py                      # real run (after the window closed)
    shape-observation-evaluate.py --rehearsal          # reader check on a historical window, never OBSERVED
    shape-observation-evaluate.py --reader-fixture f.json --now 2026-10-24T13:00:00Z   # isolated test
"""
import argparse
import datetime as dt
import json
import os
import subprocess
import sys

SCHEMA = "clawforge.shape-observation/1"
DEFAULT_WINDOW_START = "2026-10-23T12:50:00Z"   # shortly after the 1.2.5 sensor began sending the verdict
DEFAULT_HOURS = 24
MIN_VERDICT_COVERAGE = 0.99
MIN_SNAPSHOT_COVERAGE = 0.99
MAX_POLICY_HEARTBEAT_AGE = 120
MAX_SENSOR_AGE = 300
SQL_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ops", "shape-evaluation.sql")

NOT_MEASURED = {
    "false_positive_rate": "no operator-labelled legitimate bursts exist: decisions are counts, not verdicts",
    "recall_on_real_attacks": "no ground truth for real traffic; only frequencies of shapes and bases are reported",
    "behaviour_of_legitimate_shared_nat": "no real legitimate burst was observed; the lab scenarios are controlled, not population evidence",
    "enforcement_effect": "no live action exists (executor dry-run, bridge off); simulated requests are simulations",
    "gate_7b": "this observation is not the Phase 7B pilot (canary, rollback latency, lockout, drift)",
}


class InvalidInput(Exception):
    pass


def parse_utc(text):
    try:
        value = dt.datetime.fromisoformat(str(text).replace("Z", "+00:00"))
    except ValueError as error:
        raise InvalidInput(f"bad timestamp {text!r}") from error
    if value.tzinfo is None:
        raise InvalidInput(f"timestamp without timezone {text!r}")
    return value.astimezone(dt.timezone.utc)


def iso(value):
    return value.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def check(name, ok, detail):
    return {"name": name, "ok": bool(ok), "detail": detail}


def need(data, *path):
    """A missing section is missing data, never a pass."""
    node = data
    for key in path:
        if not isinstance(node, dict) or key not in node or node[key] is None:
            return None
        node = node[key]
    return node


def completeness_checks(data, hours):
    checks = []
    full = need(data, "full_hours")
    if not isinstance(full, list) or len(full) < hours - 2:
        checks.append(check("full_hours_present", False, f"{0 if not isinstance(full, list) else len(full)} full hours, need >= {hours - 2}"))
        full = full if isinstance(full, list) else []
    else:
        checks.append(check("full_hours_present", True, f"{len(full)} full hours"))
    silent = [h.get("hour") for h in full if not h.get("ssh_events")]
    checks.append(check("ssh_events_every_full_hour", not silent and bool(full), f"hours without ssh events: {silent[:6]}"))
    undecided_hours = [h.get("hour") for h in full if h.get("assessments") and not h.get("decisions")]
    checks.append(check("decisions_every_hour_with_assessments", not undecided_hours and bool(full), f"hours with assessments but no decision: {undecided_hours[:6]}"))
    ssh = need(data, "ssh_events")
    if ssh and ssh.get("total"):
        coverage = ssh.get("with_verdict", 0) / ssh["total"]
        checks.append(check("verdict_coverage", coverage >= MIN_VERDICT_COVERAGE, f"{coverage:.4f} of {ssh['total']} ssh failures carry sshd's verdict (need >= {MIN_VERDICT_COVERAGE})"))
    else:
        checks.append(check("verdict_coverage", False, "no ssh events in the window"))
    dec = need(data, "ssh_decisions")
    if dec and dec.get("total"):
        snapshot = dec.get("with_attack_shape_snapshot", 0) / dec["total"]
        checks.append(check("attack_shape_in_decision_snapshots", snapshot >= MIN_SNAPSHOT_COVERAGE, f"{snapshot:.4f} of {dec['total']} ssh decisions carry the shape counts"))
    else:
        checks.append(check("attack_shape_in_decision_snapshots", False, "no ssh decisions in the window"))
    undecided = need(data, "undecided_assessments_with_active_policy")
    checks.append(check("no_undecided_assessments", undecided == 0, f"undecided assessments with an active policy: {undecided}"))
    backlog = need(data, "delivery_backlog_security_engine")
    checks.append(check("no_delivery_backlog_for_the_window", backlog == 0, f"pending/failed security-engine deliveries for events inside the window: {backlog}"))
    policy = need(data, "policy_engine")
    ok = bool(policy) and policy.get("state") == "running" and (policy.get("heartbeat_age_seconds") is not None) and policy["heartbeat_age_seconds"] <= MAX_POLICY_HEARTBEAT_AGE
    checks.append(check("policy_engine_running_and_fresh", ok, f"policy-engine {policy}"))
    sensor = need(data, "ssh_sensor_age_seconds")
    checks.append(check("ssh_sensor_fresh", sensor is not None and sensor <= MAX_SENSOR_AGE, f"last seen {sensor} s ago (need <= {MAX_SENSOR_AGE})"))
    return checks


def evaluate(data, now, window_start, hours, rehearsal=False):
    """Pure: reader result + clock -> verdict document. The clock guard runs first and needs no data."""
    end = window_start + dt.timedelta(hours=hours)
    base = {
        "schema": SCHEMA,
        "evaluated_at": iso(now),
        "window": {"start": iso(window_start), "end": iso(end), "hours": hours},
        "operator_gate_passed": False,
        "quality_gate_verdict": None,
        "requires_operator_review": True,
        "labels_available": False,
        "rehearsal": bool(rehearsal),
        "not_measured": NOT_MEASURED,
    }
    if now < end and not rehearsal:
        return dict(base, status="TOO_EARLY", checks=[check("window_closed", False, f"window closes {iso(end)}, now {iso(now)}")], measurements=None)
    checks = [check("window_closed", now >= end, f"window closes {iso(end)}, now {iso(now)}")]
    if hours < 24:
        checks.append(check("window_at_least_24h", False, f"{hours} h requested"))
    else:
        checks.append(check("window_at_least_24h", True, f"{hours} h"))
    if data is None:
        return dict(base, status="INSUFFICIENT_DATA", checks=checks + [check("reader_result", False, "no data")], measurements=None)
    checks += completeness_checks(data, hours)
    measurements = {
        "ssh_events": need(data, "ssh_events"),
        "ssh_decisions": need(data, "ssh_decisions"),
        "decisions_by_shape_basis": need(data, "decisions_by_shape_basis"),
        "invalid_account_probe": need(data, "invalid_account_probe"),
        "assessments_in_window": need(data, "assessments_in_window"),
        "per_hour": need(data, "full_hours"),
        "schema_version": need(data, "schema_version"),
    }
    complete = all(c["ok"] for c in checks)
    if rehearsal:
        status = "REHEARSAL"
    else:
        status = "OBSERVED" if complete else "INSUFFICIENT_DATA"
    return dict(base, status=status, checks=checks, measurements=measurements)


EXIT = {"TOO_EARLY": 75, "INSUFFICIENT_DATA": 3, "REHEARSAL": 4, "OBSERVED": 0}


def read_database(window_start, window_end, container):
    sql = open(SQL_PATH, encoding="utf-8").read()
    script = "BEGIN READ ONLY;\nSET LOCAL statement_timeout='30s';\nSET LOCAL lock_timeout='2s';\n" + sql + "\nROLLBACK;\n"
    result = subprocess.run(
        ["docker", "exec", "-i", container, "psql", "-X", "-At", "-U", "clawforge", "-d", "clawforge", "-v", "ON_ERROR_STOP=1",
         "-v", f"w_start={iso(window_start)}", "-v", f"w_end={iso(window_end)}"],
        input=script, text=True, capture_output=True, timeout=75)
    if result.returncode != 0:
        raise InvalidInput("reader failed: " + result.stderr.strip()[:300])
    lines = [line for line in result.stdout.splitlines() if line.startswith("RESULT_JSON ")]
    if len(lines) != 1:
        raise InvalidInput("reader returned no single RESULT_JSON line")
    try:
        return json.loads(lines[0][len("RESULT_JSON "):])
    except ValueError as error:
        raise InvalidInput(f"reader result is not JSON: {error}") from error


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--window-start", default=DEFAULT_WINDOW_START)
    parser.add_argument("--hours", type=int, default=DEFAULT_HOURS)
    parser.add_argument("--now", help="override the clock (tests only)")
    parser.add_argument("--rehearsal", action="store_true", help="skip only the clock guard; the result is never OBSERVED")
    parser.add_argument("--reader-fixture", help="read the reader result from a JSON file instead of the database (tests)")
    parser.add_argument("--container", default="clawforge-postgres-1")
    parser.add_argument("--out", help="also write the verdict JSON here (mode 0600)")
    args = parser.parse_args(argv)
    try:
        if args.hours <= 0 or args.hours > 24 * 14:
            raise InvalidInput("hours must be 1..336")
        start = parse_utc(args.window_start)
        now = parse_utc(args.now) if args.now else dt.datetime.now(dt.timezone.utc)
        end = start + dt.timedelta(hours=args.hours)
        data = None
        if now >= end or args.rehearsal:
            if args.reader_fixture:
                with open(args.reader_fixture, encoding="utf-8") as handle:
                    data = json.load(handle)
            else:
                data = read_database(start, end, args.container)
        verdict = evaluate(data, now, start, args.hours, args.rehearsal)
    except (InvalidInput, OSError, ValueError, subprocess.TimeoutExpired) as error:
        print(json.dumps({"schema": SCHEMA, "status": "ERROR", "error": str(error), "operator_gate_passed": False,
                          "quality_gate_verdict": None, "requires_operator_review": True}))
        return 2
    text = json.dumps(verdict, indent=2, sort_keys=True)
    print(text)
    if args.out:
        fd = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text + "\n")
    return EXIT[verdict["status"]]


if __name__ == "__main__":
    sys.exit(main())
