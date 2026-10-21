#!/usr/bin/env python3
"""Reproducible accounting of a Phase 7B read-only pilot observation.

Input: the observer's ``samples.jsonl`` (one JSON object per probe attempt,
``{"timestamp", "ssh_ok", "data", "issues"}``) and its ``config.json``
(``started_at``, ``ends_at``, ``interval_seconds``). Failed probes are rows with
``ssh_ok == false``; they are attempts, not missing rows.

This tool only *measures*. It can never pass a gate: ``automatic_rule_gate_passed``
is always ``false`` and ``requires_operator_review`` always ``true``. Quantities
the observation did not measure (false positives, rollback p95, lockout, drift)
are listed under ``not_measured`` instead of being estimated. Malformed input
fails closed with exit status 2.

    pilot-observation-evaluate.py --samples samples.jsonl --config config.json
"""
import argparse
import json
import math
import statistics
import sys

SCHEMA_VERSION = 1
# A gap longer than this many probe intervals counts as an observation gap.
GAP_FACTOR = 3

NOT_MEASURED = {
    "false_positive_rate": "no classified traffic: the only block was a documentation-range canary address",
    "rollback_latency_p95": "rollback latency is a single canary sample; a percentile needs a series",
    "lockout_slo": "no management/own-address block attempt was exercised",
    "drift_detection_time": "no drift was injected; an idle system cannot show detection time",
}


class InvalidInput(Exception):
    pass


def load_config(path):
    try:
        with open(path, encoding="utf-8") as handle:
            config = json.load(handle)
        started = float(config["started_at"])
        ends = float(config["ends_at"])
        interval = float(config["interval_seconds"])
    except (OSError, ValueError, KeyError, TypeError) as error:
        raise InvalidInput(f"config unreadable: {error}") from error
    if not (math.isfinite(started) and math.isfinite(ends) and math.isfinite(interval)):
        raise InvalidInput("config contains a non-finite number")
    if interval <= 0 or ends <= started:
        raise InvalidInput("config window or interval is not positive")
    return started, ends, interval


def load_samples(path):
    rows = []
    try:
        with open(path, encoding="utf-8") as handle:
            for number, line in enumerate(handle, 1):
                if not line.strip():
                    continue
                try:
                    row = json.loads(line)
                    timestamp = float(row["timestamp"])
                    ok = row["ssh_ok"]
                except (ValueError, KeyError, TypeError) as error:
                    raise InvalidInput(f"line {number}: {error}") from error
                if not isinstance(ok, bool) or not math.isfinite(timestamp):
                    raise InvalidInput(f"line {number}: invalid ssh_ok or timestamp")
                data = row.get("data") or {}
                if ok and not isinstance(data, dict):
                    raise InvalidInput(f"line {number}: data is not an object")
                rows.append({"timestamp": timestamp, "ok": ok, "data": data,
                             "issues": list(row.get("issues") or [])})
    except OSError as error:
        raise InvalidInput(f"samples unreadable: {error}") from error
    if not rows:
        raise InvalidInput("no samples")
    for earlier, later in zip(rows, rows[1:]):
        if later["timestamp"] <= earlier["timestamp"]:
            raise InvalidInput("timestamps are not strictly increasing")
    return rows


def failure_runs(rows):
    """Contiguous runs of failed attempts as (first_ts, last_ts, length)."""
    runs, current = [], []
    for row in rows:
        if not row["ok"]:
            current.append(row["timestamp"])
        elif current:
            runs.append((current[0], current[-1], len(current)))
            current = []
    if current:
        runs.append((current[0], current[-1], len(current)))
    return runs


def evaluate(rows, started, ends, interval):
    successful = [row for row in rows if row["ok"]]
    failed = len(rows) - len(successful)
    stamps = [row["timestamp"] for row in rows]
    gaps = [later - earlier for earlier, later in zip(stamps, stamps[1:])]
    good_stamps = [row["timestamp"] for row in successful]
    good_gaps = [later - earlier for earlier, later in zip(good_stamps, good_stamps[1:])]
    limit = interval * GAP_FACTOR
    runs = failure_runs(rows)
    window = ends - started
    nominal = math.floor(window / interval)

    data_rows = [row["data"] for row in successful]

    def peak(key):
        values = [d.get(key) for d in data_rows if isinstance(d.get(key), (int, float))]
        return max(values) if values else None

    active = [d.get("active_elements") or {} for d in data_rows]
    active_peak = max((sum(v for v in a.values() if isinstance(v, int)) for a in active), default=None)
    issue_counts = {}
    for row in rows:
        for issue in row["issues"]:
            issue_counts[issue] = issue_counts.get(issue, 0) + 1
    violations = {
        "unresolved_generations_peak": peak("unresolved_generations"),
        "executable_requests_peak": peak("executable_requests"),
        "active_block_elements_peak": active_peak,
        "samples_with_running_executor": sum(1 for d in data_rows if d.get("running_executors")),
        "samples_with_unhealthy_api": sum(1 for d in data_rows if d.get("api_healthy") is False),
    }
    invariant_ok = (
        bool(successful)
        and not violations["unresolved_generations_peak"]
        and not violations["executable_requests_peak"]
        and not violations["active_block_elements_peak"]
        and violations["samples_with_running_executor"] == 0
        and violations["samples_with_unhealthy_api"] == 0
        and set(issue_counts) <= {"telemetry_unavailable"}
    )
    first_delay = stamps[0] - started
    tail_gap = ends - stamps[-1]
    over_limit = sum(1 for gap in gaps if gap > limit)
    window_covered = first_delay <= limit and tail_gap <= limit

    blockers = []
    if failed:
        blockers.append("telemetry_failures_present")
    if over_limit or not window_covered:
        blockers.append("observation_gap_over_limit")
    if not invariant_ok:
        blockers.append("state_invariant_violated_or_unobserved")
    blockers.extend(f"{name}_not_measured" for name in NOT_MEASURED)

    return {
        "schema_version": SCHEMA_VERSION,
        "window": {"started_at": started, "ends_at": ends, "seconds": window,
                   "interval_seconds": interval},
        "sampling": {
            "nominal_expected_samples": nominal,
            "recorded_attempts": len(rows),
            "successful_probes": len(successful),
            "failed_probes": failed,
            "failure_ratio_of_attempts": round(failed / len(rows), 6),
            "nominal_cadence_shortfall": nominal - len(rows),
            "observed_cycle_seconds_mean": round(statistics.fmean(gaps), 3) if gaps else None,
            "largest_gap_between_attempts_seconds": round(max(gaps), 3) if gaps else None,
            "largest_gap_between_successful_probes_seconds": round(max(good_gaps), 3) if good_gaps else None,
            "gaps_over_limit": over_limit,
            "gap_limit_seconds": limit,
            "first_attempt_delay_seconds": round(first_delay, 3),
            "tail_gap_seconds": round(tail_gap, 3),
            "failure_runs": len(runs),
            "longest_failure_run_attempts": max((run[2] for run in runs), default=0),
        },
        "state": {**violations, "issues": issue_counts, "invariants_hold": invariant_ok},
        "measured": ["sampling_accounting", "idle_state_invariants"],
        "not_measured": NOT_MEASURED,
        "gate": {
            "automatic_rule_gate_passed": False,
            "requires_operator_review": True,
            "blockers": blockers,
            "note": "This tool measures only; it never passes a gate.",
        },
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--samples", required=True)
    parser.add_argument("--config", required=True)
    args = parser.parse_args(argv)
    try:
        started, ends, interval = load_config(args.config)
        report = evaluate(load_samples(args.samples), started, ends, interval)
    except InvalidInput as error:
        print(f"invalid input: {error}", file=sys.stderr)
        return 2
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
