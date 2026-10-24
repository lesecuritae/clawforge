#!/usr/bin/env python3
"""Phase 7B observation: pre-registered plan, bounded read-only probe, accounting that never passes a gate.

The first 48 h window (docs/phase7-pilot-evidence-20261021.md) recorded 2676 attempts, 168 of them failed
(`telemetry_unavailable`) and everything else was an idle-system health probe. This tool exists so that the next
window is judged against criteria fixed BEFORE it starts, and so that idle probes can never stand in for
measurements that need real events.

    phase7b-observe.py plan      --out plan.json --start ISO --hours 48 --probe-argv-json '["ssh", ...]' [...]
    phase7b-observe.py probe     --plan plan.json --samples samples.jsonl [--max-cycles N]
    phase7b-observe.py evaluate  --plan plan.json --samples samples.jsonl [--measurements m.jsonl] [--now ISO]

Rules (all enforced in code, tested in scripts/test-phase7b-observe.py):
  * `probe` is read-only: it runs the configured argv (no shell), never writes to the host it observes, installs no
    timer and is bounded by the plan window, `max_runtime_seconds` and a stop file.
  * Every attempt is a row. A failed attempt stays a failed attempt; a cycle is ok only if one attempt returned a
    valid snapshot. Failures are classified (timeout / transport / invalid_output) and never reclassified as success.
  * `evaluate` NEVER sets `gate_passed` to true. Criteria that need real events (false positives, rollback p95,
    lockout, drift, packet effect) are computed only from `measurements.jsonl`; idle health probes never count.
  * Labels are kept apart: `operator` labels, `lab_controlled` labels and `unknown` are separate counters.
  * A plan without `operator_confirmed_by` cannot reach CRITERIA_MET_REQUIRES_OPERATOR_REVIEW.
"""
import argparse
import datetime as dt
import hashlib
import json
import math
import os
import subprocess
import sys
import time

SCHEMA = 1
EXIT = {"OK": 0, "BAD_INPUT": 2, "OPERATOR_STOP": 3, "TELEMETRY_STOP": 4, "STATE_STOP": 5}

CRITERIA_DEFAULTS = {
    # Telemetry (judged on cycles, i.e. after the in-cycle retries)
    "min_cycle_availability": 0.99,
    "max_consecutive_failed_cycles": 3,
    "max_success_gap_seconds": 300,
    # Events that only a real canary / controlled test can produce
    "min_canary_measurements": 10,
    "max_rollback_p95_seconds": 5.0,
    "max_receipt_after_deadline_seconds": 5.0,
    "min_lockout_probes": 20,
    "max_drift_detection_seconds": 10.0,
    "min_drift_injections": 3,
    "max_accepted_false_positives": 0,
    "min_operator_labelled_targets": 5,
}
PROBE_DEFAULTS = {
    "interval_seconds": 60,
    "attempts_per_cycle": 3,
    "attempt_timeout_seconds": 20,
    "backoff_seconds": [2, 5],
    "max_runtime_seconds": None,
    "stop_file": None,
}
REQUIRED_SNAPSHOT_KEYS = ("unresolved_generations", "executable_requests", "active_elements", "running_executors", "api_healthy")
STATE_VIOLATIONS_STOP = True


class BadInput(Exception):
    pass


def parse_time(text):
    try:
        value = dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
    except (AttributeError, ValueError) as error:
        raise BadInput(f"not an ISO time: {text!r}") from error
    if value.tzinfo is None:
        raise BadInput(f"time needs a UTC offset: {text!r}")
    return value.astimezone(dt.timezone.utc).timestamp()


def iso(ts):
    return dt.datetime.fromtimestamp(ts, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def canonical_hash(plan):
    body = {k: v for k, v in plan.items() if k not in ("plan_sha256", "operator_confirmed_by", "operator_confirmed_at")}
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def build_plan(start_ts, hours, probe_argv, probe=None, criteria=None, note=""):
    if not (isinstance(probe_argv, list) and probe_argv and all(isinstance(a, str) for a in probe_argv)):
        raise BadInput("probe argv must be a non-empty list of strings (no shell)")
    if not 1 <= hours <= 168:
        raise BadInput("window must be 1..168 hours")
    plan = {
        "schema": SCHEMA,
        "kind": "phase7b-observation-plan",
        "window": {"start": iso(start_ts), "end": iso(start_ts + hours * 3600), "hours": hours},
        "probe": {**PROBE_DEFAULTS, **(probe or {}), "argv": probe_argv},
        "criteria": {**CRITERIA_DEFAULTS, **(criteria or {})},
        "note": note,
        "operator_confirmed_by": None,
        "operator_confirmed_at": None,
    }
    validate_plan(plan)
    plan["plan_sha256"] = canonical_hash(plan)
    return plan


def validate_plan(plan):
    try:
        window = plan["window"]
        start, end = parse_time(window["start"]), parse_time(window["end"])
        probe, criteria = plan["probe"], plan["criteria"]
        interval = float(probe["interval_seconds"])
        attempts = int(probe["attempts_per_cycle"])
        timeout = float(probe["attempt_timeout_seconds"])
        backoff = [float(b) for b in probe["backoff_seconds"]]
        argv = probe["argv"]
    except (KeyError, TypeError, ValueError) as error:
        raise BadInput(f"plan incomplete: {error}") from error
    if end <= start or interval <= 0 or attempts < 1 or timeout <= 0:
        raise BadInput("plan window/interval/attempts/timeout are not positive")
    if attempts > 1 and len(backoff) < attempts - 1:
        raise BadInput("backoff list shorter than attempts_per_cycle - 1")
    worst_cycle = attempts * timeout + sum(backoff[: attempts - 1])
    if worst_cycle >= interval * 3:
        raise BadInput(f"worst-case cycle {worst_cycle:.0f}s must stay below 3 intervals so a failing link cannot hide a gap")
    if not (isinstance(argv, list) and argv and all(isinstance(a, str) for a in argv)):
        raise BadInput("probe argv invalid")
    for name in CRITERIA_DEFAULTS:
        if name not in criteria or not isinstance(criteria[name], (int, float)) or isinstance(criteria[name], bool):
            raise BadInput(f"criterion {name} missing or not numeric")
    if not 0 < criteria["min_cycle_availability"] <= 1:
        raise BadInput("min_cycle_availability must be in (0, 1]")
    return start, end


def load_plan(path):
    try:
        with open(path, encoding="utf-8") as handle:
            plan = json.load(handle)
    except (OSError, ValueError) as error:
        raise BadInput(f"plan unreadable: {error}") from error
    validate_plan(plan)
    if plan.get("plan_sha256") != canonical_hash(plan):
        raise BadInput("plan_sha256 does not match the plan content (criteria were edited after registration)")
    return plan


def load_jsonl(path, required=()):
    rows = []
    try:
        with open(path, encoding="utf-8") as handle:
            for number, line in enumerate(handle, 1):
                if not line.strip():
                    continue
                try:
                    row = json.loads(line)
                except ValueError as error:
                    raise BadInput(f"{path} line {number}: {error}") from error
                if not isinstance(row, dict):
                    raise BadInput(f"{path} line {number}: not an object")
                for key in required:
                    if key not in row:
                        raise BadInput(f"{path} line {number}: missing {key}")
                rows.append(row)
    except FileNotFoundError:
        return []
    except OSError as error:
        raise BadInput(f"{path} unreadable: {error}") from error
    return rows


# --------------------------------------------------------------------------- probe

def snapshot_problems(data):
    """State-invariant violations in a valid snapshot (idle expectations before/between canaries)."""
    problems = []
    if data.get("unresolved_generations"):
        problems.append("unresolved_generations")
    if data.get("executable_requests"):
        problems.append("executable_requests")
    elements = data.get("active_elements") or {}
    if any(isinstance(v, int) and v for v in elements.values()):
        problems.append("unexpected_active_block")
    if data.get("running_executors"):
        problems.append("unexpected_running_executor")
    if data.get("api_healthy") is not True:
        problems.append("api_unhealthy")
    return problems


def run_attempt(argv, timeout):
    started = time.time()
    try:
        done = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, stdin=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        return {"ok": False, "error_class": "timeout", "duration_s": round(time.time() - started, 3)}
    except OSError:
        return {"ok": False, "error_class": "transport", "duration_s": round(time.time() - started, 3)}
    duration = round(time.time() - started, 3)
    if done.returncode != 0:
        return {"ok": False, "error_class": "transport", "returncode": done.returncode, "duration_s": duration}
    try:
        data = json.loads(done.stdout)
        if not isinstance(data, dict) or any(k not in data for k in REQUIRED_SNAPSHOT_KEYS):
            raise ValueError("missing snapshot keys")
    except ValueError:
        return {"ok": False, "error_class": "invalid_output", "duration_s": duration}
    return {"ok": True, "data": data, "duration_s": duration}


def probe(plan, samples_path, max_cycles=None, now=time.time, sleep=time.sleep, attempt_fn=run_attempt):
    start, end = validate_plan(plan)
    cfg = plan["probe"]
    began = now()
    cycle = len(load_jsonl(samples_path))  # continues numbering; rows are append-only
    consecutive_failed = 0
    done_cycles = 0
    limit = plan["criteria"]["max_consecutive_failed_cycles"]
    while True:
        t = now()
        if t < start - cfg["interval_seconds"]:
            return EXIT["BAD_INPUT"], "window has not started (refusing to sample early)"
        if t < start:
            sleep(start - t)
            continue
        if t >= end:
            return EXIT["OK"], "window elapsed"
        if cfg.get("stop_file") and os.path.exists(cfg["stop_file"]):
            append(samples_path, {"timestamp": t, "event": "operator_stop", "cycle": cycle})
            return EXIT["OPERATOR_STOP"], "stop file present"
        if cfg.get("max_runtime_seconds") and t - began >= cfg["max_runtime_seconds"]:
            return EXIT["OK"], "runtime bound reached (window not complete)"
        if max_cycles is not None and done_cycles >= max_cycles:
            return EXIT["OK"], "max cycles reached"
        cycle += 1
        done_cycles += 1
        cycle_start = now()
        attempts = []
        result = None
        for number in range(1, cfg["attempts_per_cycle"] + 1):
            outcome = attempt_fn(cfg["argv"], cfg["attempt_timeout_seconds"])
            attempts.append({k: v for k, v in outcome.items() if k != "data"} | {"attempt": number})
            if outcome["ok"]:
                result = outcome["data"]
                break
            if number < cfg["attempts_per_cycle"]:
                sleep(cfg["backoff_seconds"][number - 1])
        problems = snapshot_problems(result) if result is not None else []
        row = {"timestamp": cycle_start, "cycle": cycle, "ssh_ok": result is not None, "attempts": attempts,
               "data": result or {}, "issues": problems if result is not None else ["telemetry_unavailable"]}
        append(samples_path, row)
        consecutive_failed = 0 if result is not None else consecutive_failed + 1
        if problems and STATE_VIOLATIONS_STOP:
            return EXIT["STATE_STOP"], f"state invariant violated: {','.join(problems)}"
        if consecutive_failed > limit:
            return EXIT["TELEMETRY_STOP"], f"{consecutive_failed} consecutive failed cycles (limit {limit}); operator must look"
        wait = cfg["interval_seconds"] - (now() - cycle_start)
        if wait > 0:
            sleep(min(wait, max(0.0, end - now())))


def append(path, row):
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    with os.fdopen(fd, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(row, sort_keys=True) + "\n")
        handle.flush()
        os.fsync(handle.fileno())


# ------------------------------------------------------------------------ evaluate

def percentile_nearest_rank(values, q):
    ordered = sorted(values)
    return ordered[max(0, math.ceil(q * len(ordered)) - 1)]


def verdict(name, met, detail, measured=True):
    return {"criterion": name, "status": "not_measured" if not measured else ("met" if met else "not_met"), "detail": detail}


def evaluate(plan, samples, measurements, now_ts):
    start, end = validate_plan(plan)
    criteria = plan["criteria"]
    interval = plan["probe"]["interval_seconds"]
    inside = [s for s in samples if "event" not in s and start <= float(s["timestamp"]) < end]
    outside = len([s for s in samples if "event" not in s]) - len(inside)
    stops = [s for s in samples if s.get("event") == "operator_stop"]
    cycles = sorted(inside, key=lambda s: s["timestamp"])
    ok_cycles = [s for s in cycles if s.get("ssh_ok") is True]
    attempts = [a for s in cycles for a in (s.get("attempts") or [{"ok": s.get("ssh_ok") is True, "error_class": None if s.get("ssh_ok") else "telemetry_unavailable"}])]
    failed_attempts = [a for a in attempts if not a.get("ok")]
    runs, current, longest = 0, 0, 0
    for s in cycles:
        if s.get("ssh_ok") is True:
            current = 0
        else:
            if current == 0:
                runs += 1
            current += 1
            longest = max(longest, current)
    good_times = [float(s["timestamp"]) for s in ok_cycles]
    gap_points = [start] + good_times + [min(now_ts, end)]
    max_success_gap = max((b - a for a, b in zip(gap_points, gap_points[1:])), default=end - start)
    elapsed = min(now_ts, end) - start
    window_complete = now_ts >= end
    availability = len(ok_cycles) / len(cycles) if cycles else None
    state_issues = sorted({i for s in ok_cycles for i in (s.get("issues") or [])})
    expected_cycles = max(1, math.floor(elapsed / interval)) if elapsed > 0 else 0
    coverage = len(cycles) / expected_cycles if expected_cycles else 0.0

    results = []
    results.append(verdict("window_complete_and_covered", window_complete and coverage >= 0.95,
                           f"window {'elapsed' if window_complete else 'still open'}; cycles {len(cycles)}/{expected_cycles} expected ({coverage:.3f})", bool(cycles) and window_complete))
    results.append(verdict("cycle_availability", availability is not None and availability >= criteria["min_cycle_availability"],
                           f"{len(ok_cycles)} ok of {len(cycles)} cycles = {availability if availability is None else round(availability, 5)}; need >= {criteria['min_cycle_availability']}", bool(cycles)))
    results.append(verdict("max_consecutive_failed_cycles", longest <= criteria["max_consecutive_failed_cycles"],
                           f"longest run {longest} cycles in {runs} runs; limit {criteria['max_consecutive_failed_cycles']}", bool(cycles)))
    results.append(verdict("max_gap_between_successful_cycles", max_success_gap <= criteria["max_success_gap_seconds"],
                           f"{round(max_success_gap, 1)} s; limit {criteria['max_success_gap_seconds']} s", bool(cycles)))
    results.append(verdict("idle_state_invariants", not state_issues and bool(ok_cycles), f"issues seen in valid snapshots: {state_issues or 'none'}", bool(ok_cycles)))

    canaries = [m for m in measurements if m.get("type") == "canary"]
    complete_canaries = [m for m in canaries if all(isinstance(m.get(k), (int, float)) for k in ("rollback_seconds", "receipt_after_deadline_seconds"))]
    real = [m for m in complete_canaries if not m.get("lab") and m.get("distinct_human_approvals", 0) >= 2]
    enough = len(real) >= criteria["min_canary_measurements"]
    if enough:
        p95 = percentile_nearest_rank([m["rollback_seconds"] for m in real], 0.95)
        late = max(m["receipt_after_deadline_seconds"] for m in real)
        results.append(verdict("rollback_p95", p95 <= criteria["max_rollback_p95_seconds"], f"p95 {p95} s over {len(real)} approved real canaries; limit {criteria['max_rollback_p95_seconds']}"))
        results.append(verdict("receipt_after_deadline", late <= criteria["max_receipt_after_deadline_seconds"], f"worst {late} s; limit {criteria['max_receipt_after_deadline_seconds']}"))
        packet_ok = all(m.get("baseline_ok") is True and m.get("blocked_dropped") is True and m.get("restored_ok") is True for m in real)
        results.append(verdict("packet_effect_each_canary", packet_ok, f"baseline passed, blocked dropped, restored passed in {sum(1 for m in real if m.get('baseline_ok') and m.get('blocked_dropped') and m.get('restored_ok'))}/{len(real)}"))
    else:
        reason = f"{len(real)} approved real canaries with complete numbers ({len(canaries)} canary rows, {len(canaries) - len(real)} lab/unapproved/incomplete excluded); need {criteria['min_canary_measurements']}"
        for name in ("rollback_p95", "receipt_after_deadline", "packet_effect_each_canary"):
            results.append(verdict(name, False, reason, measured=False))

    probes = [m for m in measurements if m.get("type") == "lockout_probe"]
    if len(probes) >= criteria["min_lockout_probes"]:
        leaked = [p for p in probes if p.get("refused") is not True]
        results.append(verdict("lockout_protection", not leaked, f"{len(probes) - len(leaked)}/{len(probes)} protected addresses refused"))
    else:
        results.append(verdict("lockout_protection", False, f"{len(probes)} lockout probes; need {criteria['min_lockout_probes']}", measured=False))

    drifts = [m for m in measurements if m.get("type") == "drift_injection" and isinstance(m.get("injected_at"), (int, float))]
    if len(drifts) >= criteria["min_drift_injections"]:
        undetected = [d for d in drifts if not isinstance(d.get("detected_at"), (int, float))]
        times = [d["detected_at"] - d["injected_at"] for d in drifts if d not in undetected]
        worst = max(times) if times else None
        results.append(verdict("drift_detection", not undetected and worst is not None and worst <= criteria["max_drift_detection_seconds"],
                               f"{len(undetected)} undetected of {len(drifts)}; worst {worst}s; limit {criteria['max_drift_detection_seconds']}s"))
    else:
        results.append(verdict("drift_detection", False, f"{len(drifts)} drift injections; need {criteria['min_drift_injections']}", measured=False))

    labels = {"operator": 0, "lab_controlled": 0, "unknown": 0}
    accepted_fp = 0
    for m in measurements:
        if m.get("type") != "false_positive_review":
            continue
        source = m.get("label_source") if m.get("label_source") in labels else "unknown"
        labels[source] += 1
        if source == "operator" and m.get("classification") == "legitimate" and m.get("was_blocked"):
            accepted_fp += 1
    if labels["operator"] >= criteria["min_operator_labelled_targets"]:
        results.append(verdict("false_positives", accepted_fp <= criteria["max_accepted_false_positives"],
                               f"{accepted_fp} legitimate targets blocked among {labels['operator']} operator-labelled; lab_controlled {labels['lab_controlled']} and unknown {labels['unknown']} do not count"))
    else:
        results.append(verdict("false_positives", False, f"{labels['operator']} operator-labelled targets (lab_controlled {labels['lab_controlled']}, unknown {labels['unknown']} excluded); need {criteria['min_operator_labelled_targets']}", measured=False))

    confirmed = bool(plan.get("operator_confirmed_by"))
    not_met = [r["criterion"] for r in results if r["status"] == "not_met"]
    not_measured = [r["criterion"] for r in results if r["status"] == "not_measured"]
    if not_met:
        status = "CRITERIA_NOT_MET"
    elif not_measured or not window_complete:
        status = "INSUFFICIENT_EVIDENCE"
    elif not confirmed:
        status = "INSUFFICIENT_EVIDENCE"
    else:
        status = "CRITERIA_MET_REQUIRES_OPERATOR_REVIEW"
    reasons = []
    if not confirmed:
        reasons.append("plan_not_confirmed_by_operator")
    if not window_complete:
        reasons.append("window_still_open")
    if outside:
        reasons.append(f"{outside}_cycle_rows_outside_window_ignored")
    if stops:
        reasons.append("operator_stop_recorded")
    return {
        "schema": SCHEMA,
        "evaluated_at": iso(now_ts),
        "plan_sha256": plan["plan_sha256"],
        "status": status,
        "gate_passed": False,
        "requires_operator_review": True,
        "reasons": reasons,
        "accounting": {
            "cycles": len(cycles), "ok_cycles": len(ok_cycles), "failed_cycles": len(cycles) - len(ok_cycles),
            "attempts": len(attempts), "failed_attempts": len(failed_attempts),
            "failed_attempt_classes": {c: sum(1 for a in failed_attempts if a.get("error_class") == c) for c in sorted({a.get("error_class") for a in failed_attempts if a.get("error_class")})},
            "failure_runs": runs, "longest_failure_run_cycles": longest,
            "max_gap_between_successful_cycles_seconds": round(max_success_gap, 1),
            "label_counts": labels,
        },
        "criteria": results,
        "not_met": not_met,
        "not_measured": not_measured,
        "note": "Idle health probes satisfy only the telemetry and idle-invariant criteria. This tool measures; it never passes a gate.",
    }


# ------------------------------------------------------------------------------ cli

def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("plan")
    p.add_argument("--out", required=True)
    p.add_argument("--start", required=True)
    p.add_argument("--hours", type=float, default=48)
    p.add_argument("--probe-argv-json", required=True)
    p.add_argument("--stop-file")
    p.add_argument("--max-runtime-seconds", type=int)
    p.add_argument("--note", default="")
    q = sub.add_parser("probe")
    q.add_argument("--plan", required=True)
    q.add_argument("--samples", required=True)
    q.add_argument("--max-cycles", type=int)
    e = sub.add_parser("evaluate")
    e.add_argument("--plan", required=True)
    e.add_argument("--samples", required=True)
    e.add_argument("--measurements")
    e.add_argument("--now")
    e.add_argument("--out")
    args = parser.parse_args(argv)
    try:
        if args.cmd == "plan":
            probe_cfg = {k: v for k, v in (("stop_file", args.stop_file), ("max_runtime_seconds", args.max_runtime_seconds)) if v}
            plan = build_plan(parse_time(args.start), args.hours, json.loads(args.probe_argv_json), probe_cfg, note=args.note)
            fd = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(plan, handle, indent=2, sort_keys=True)
                handle.write("\n")
            print(json.dumps({"plan": args.out, "plan_sha256": plan["plan_sha256"], "operator_confirmed_by": None}))
            return EXIT["OK"]
        plan = load_plan(args.plan)
        if args.cmd == "probe":
            code, message = probe(plan, args.samples, args.max_cycles)
            print(json.dumps({"exit": code, "message": message}))
            return code
        samples = load_jsonl(args.samples, required=("timestamp",)) if os.path.exists(args.samples) else []
        for row in samples:
            float(row["timestamp"])
        measurements = load_jsonl(args.measurements) if args.measurements else []
        report = evaluate(plan, samples, measurements, parse_time(args.now) if args.now else time.time())
        text = json.dumps(report, indent=2, sort_keys=True)
        if args.out:
            fd = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(text + "\n")
        print(text)
        return EXIT["OK"]
    except (BadInput, ValueError, FileExistsError) as error:
        print(json.dumps({"error": str(error), "gate_passed": False}))
        return EXIT["BAD_INPUT"]


if __name__ == "__main__":
    sys.exit(main())
