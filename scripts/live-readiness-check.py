#!/usr/bin/env python3
"""Read-only live-readiness checklist: the real production state against the operator-reviewed limits.

It makes the remaining live requirements checkable. It can NEVER declare the system live-ready:
``live_ready`` is always ``false`` and ``outstanding_human_items`` always lists what no script can supply
(two independent human approvals, operator-labelled legitimate traffic, a passed Phase 7B observation, a
maintenance-window reboot validation, the operator's protection values). Unknowns stay UNKNOWN.

  gates_closed      what must still be closed today (PASS = closed). FAIL means something was opened.
  prerequisites     what must hold before a canary may be proposed (PASS / FAIL / UNKNOWN).
  warnings          true observations that are not blockers.

    live-readiness-check.py [--shape-verdict verdict.json] [--backup-dir DIR] [--out report.json]
    live-readiness-check.py --collected-fixture state.json      (isolated tests)
Exit 0 always for a produced report (the report is the result), 2 on a collector failure.
"""
import argparse
import json
import os
import subprocess
import sys
import datetime as dt

SCHEMA = "clawforge.live-readiness/1"
# Reviewed pilot limits (docs/phase7-pilot-limits.md, operator-confirmed 2026-10-08).
PILOT = {"max_ttl_seconds": 900, "max_applies_per_window": 2, "rate_window_seconds": 300, "max_concurrent": 5}
FRESH_RUNTIME_SECONDS = 120
FRESH_SENSOR_SECONDS = 300
COUNTING_FEEDS = ("spamhaus_drop", "spamhaus_edrop", "spamhaus_asn", "feodo_tracker")

OUTSTANDING_HUMAN_ITEMS = [
    "two independent, context-bound human approvals per request (cannot be created by an agent)",
    "operator-labelled legitimate traffic: the false-positive rate is unmeasurable without it",
    "a passed Phase 7B observation with predefined outage/lockout/restore criteria (the 24 h shape evaluation is not it)",
    "the operator's own protection values (management network, own ISP/VPN, DNS, gateway) in CLAWFORGE_FIREWALL_NEVER_BLOCK_CIDRS",
    "a maintenance-window guest-reboot validation of the passive IDS mirror (never done on the production VM)",
    "an explicit live authorization and the operator's decision to open the gate",
]


def item(item_id, status, detail):
    assert status in ("PASS", "FAIL", "UNKNOWN")
    return {"id": item_id, "status": status, "detail": detail}


def as_int(value):
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def evaluate(state, now):
    env = state.get("executor_env") or {}
    gates, prereq, warnings = [], [], []

    # ---- gates that must be closed today ------------------------------------------------------
    gates.append(item("executor_dry_run", "PASS" if env.get("CLAWFORGE_EXECUTOR_DRY_RUN") == "true" else "FAIL", f"CLAWFORGE_EXECUTOR_DRY_RUN={env.get('CLAWFORGE_EXECUTOR_DRY_RUN')!r}"))
    gates.append(item("no_live_authorization", "PASS" if not (env.get("CLAWFORGE_EXECUTOR_LIVE_AUTHORIZATION") or "").strip() else "FAIL", "live authorization " + ("present" if (env.get("CLAWFORGE_EXECUTOR_LIVE_AUTHORIZATION") or "").strip() else "absent")))
    bridge = (state.get("policy_engine_env") or {}).get("CLAWFORGE_POLICY_BRIDGE_MODE") or ""
    gates.append(item("bridge_off", "PASS" if bridge.strip() == "" else "FAIL", f"CLAWFORGE_POLICY_BRIDGE_MODE={bridge!r}"))
    enabled = [a for a in state.get("actions", []) if a.get("enabled")]
    gates.append(item("all_actions_disabled", "PASS" if state.get("actions") and not enabled else ("UNKNOWN" if not state.get("actions") else "FAIL"), f"enabled actions: {[a['name'] for a in enabled][:6]}"))
    policies = state.get("policies", [])
    non_observe = [p["name"] for p in policies if p.get("status") == "active" and p.get("class") != "observe"]
    gates.append(item("active_policies_observe_only", "PASS" if policies and not non_observe else ("UNKNOWN" if not policies else "FAIL"), f"active non-observe policies: {non_observe[:6]}"))
    gates.append(item("ripestat_enrichment_unchanged_off", "PASS" if not (state.get("worker_env") or {}).get("CLAWFORGE_ENABLE_IP_CONTEXT") else "FAIL", "CLAWFORGE_ENABLE_IP_CONTEXT " + ("set" if (state.get("worker_env") or {}).get("CLAWFORGE_ENABLE_IP_CONTEXT") else "unset")))

    # ---- prerequisites before a canary may be proposed ----------------------------------------
    never = [e for e in (env.get("CLAWFORGE_FIREWALL_NEVER_BLOCK_CIDRS") or "").split(",") if e.strip()]
    prereq.append(item("never_block_list_defined", "PASS" if never else "FAIL", f"{len(never)} operator-defined protected range(s) (built-in loopback/link-local alone is not a decision)"))
    ttl = as_int(env.get("CLAWFORGE_FIREWALL_MAX_TTL_SECONDS"))
    prereq.append(item("ttl_ceiling_at_pilot_limit", "PASS" if ttl is not None and ttl <= PILOT["max_ttl_seconds"] else "FAIL", f"CLAWFORGE_FIREWALL_MAX_TTL_SECONDS={ttl!r} (reviewed pilot limit {PILOT['max_ttl_seconds']}; code default 3600)"))
    applies = as_int(env.get("CLAWFORGE_FIREWALL_MAX_APPLIES_PER_WINDOW"))
    window = as_int(env.get("CLAWFORGE_FIREWALL_RATE_WINDOW_SECONDS"))
    ok = applies is not None and applies <= PILOT["max_applies_per_window"] and (window or PILOT["rate_window_seconds"]) >= PILOT["rate_window_seconds"]
    prereq.append(item("apply_budget_at_pilot_limit", "PASS" if ok else "FAIL", f"MAX_APPLIES_PER_WINDOW={applies!r} window={window!r} (reviewed {PILOT['max_applies_per_window']} per {PILOT['rate_window_seconds']} s; code default 20)"))
    conc = as_int(env.get("CLAWFORGE_FIREWALL_MAX_CONCURRENT_APPLIES_PER_ADAPTER"))
    prereq.append(item("concurrency_budget_explicit", "PASS" if conc is not None and conc <= PILOT["max_concurrent"] else "FAIL", f"MAX_CONCURRENT_APPLIES_PER_ADAPTER={conc!r} (reviewed <= {PILOT['max_concurrent']}; code default 5)"))
    runtime = {r["component"]: r for r in state.get("runtime", [])}
    for component in ("policy-engine", "security-engine", "executor", "worker", "correlation", "api", "incidents"):
        r = runtime.get(component)
        if not r:
            prereq.append(item(f"runtime_{component}", "UNKNOWN", "no runtime_status row"))
            continue
        good = r.get("state") == "running" and r.get("heartbeat_age_seconds") is not None and r["heartbeat_age_seconds"] <= FRESH_RUNTIME_SECONDS
        prereq.append(item(f"runtime_{component}", "PASS" if good else "FAIL", f"state={r.get('state')} heartbeat_age={r.get('heartbeat_age_seconds')} s (need <= {FRESH_RUNTIME_SECONDS})"))
    orphans = state.get("orphan_security_definer_functions")
    prereq.append(item("no_orphaned_security_definer_functions", "UNKNOWN" if orphans is None else ("PASS" if not orphans else "FAIL"), f"orphans: {orphans}"))
    stale_sensors = [s["name"] for s in state.get("sensors", []) if s.get("age_seconds") is None or s["age_seconds"] > FRESH_SENSOR_SECONDS]
    prereq.append(item("all_sensors_fresh", "PASS" if state.get("sensors") and not stale_sensors else ("UNKNOWN" if not state.get("sensors") else "FAIL"), f"stale or never-seen sensors: {stale_sensors}"))
    feeds = {f["id"]: f for f in state.get("providers", [])}
    for feed in COUNTING_FEEDS:
        f = feeds.get(feed)
        if not f:
            prereq.append(item(f"feed_{feed}", "UNKNOWN", "provider not found"))
            continue
        limit = 2 * (f.get("interval_seconds") or 3600)
        good = f.get("enabled") and f.get("state") == "ok" and f.get("last_success_age_seconds") is not None and f["last_success_age_seconds"] <= limit
        prereq.append(item(f"feed_{feed}", "PASS" if good else "FAIL", f"state={f.get('state')} last success {f.get('last_success_age_seconds')} s ago (need <= {limit})"))
    # The bridge applies ONE age to the decision, the assessment AND the reputation listing. Counting feeds reconfirm
    # a listing only at their sync (hourly for Spamhaus), so a listing is "fresh" for just age / interval of each cycle
    # when the age is shorter than the interval; the refusal then reads threat_intel_required, as if it were unlisted.
    mode = ((state.get("policy_engine_env") or {}).get("CLAWFORGE_POLICY_BRIDGE_MODE") or "").strip()
    if mode in ("", "off"):
        prereq.append(item("bridge_evidence_age_covers_feed_cadence", "PASS", "bridge off: not applicable until a mode is chosen (then the evidence age must be >= 2x the slowest counting feed interval)"))
    else:
        raw = ((state.get("policy_engine_env") or {}).get("CLAWFORGE_POLICY_BRIDGE_MAX_EVIDENCE_AGE_SECONDS") or "").strip()
        intervals = [f.get("interval_seconds") for f in feeds.values() if f["id"] in COUNTING_FEEDS and f.get("enabled") and f.get("interval_seconds")]
        if not raw.isdigit() or not intervals:
            prereq.append(item("bridge_evidence_age_covers_feed_cadence", "UNKNOWN", f"evidence age {raw!r}, counting feed intervals {intervals}"))
        else:
            need = 2 * max(intervals)
            prereq.append(item("bridge_evidence_age_covers_feed_cadence", "PASS" if int(raw) >= need else "FAIL",
                               f"MAX_EVIDENCE_AGE={raw} s, need >= {need} s (2x the slowest counting feed, {max(intervals)} s); a shorter age refuses a genuinely listed source for part of every sync cycle"))
    failing = [f["id"] for f in state.get("providers", []) if f.get("enabled") and f.get("state") == "error"]
    if failing:
        warnings.append(f"enabled providers in error (not counting feeds, e.g. missing abuse.ch AuthKeys): {failing}")
    backup = state.get("backup")
    if backup is None:
        prereq.append(item("recent_restorable_backup", "UNKNOWN", "backup volume not readable by this check; nothing is assumed"))
    else:
        prereq.append(item("recent_restorable_backup", "PASS" if backup.get("files") and (backup.get("newest_age_seconds") or 10**9) <= 100000 and (backup.get("newest_bytes") or 0) > 10_000_000_000 else "FAIL", f"{backup.get('files')} dump(s), newest {backup.get('newest_age_seconds')} s old, {backup.get('newest_bytes')} bytes (a restore was NOT performed)"))
        if backup.get("free_gib") is not None and backup.get("newest_bytes"):
            days = backup.get("retention_days") or 14
            need = days * backup["newest_bytes"] / 2**30
            if need > backup["free_gib"]:
                warnings.append(f"backup retention {days} d x newest dump ({backup['newest_bytes'] / 2**30:.1f} GiB) = {need:.0f} GiB exceeds {backup['free_gib']:.0f} GiB free")
    verdict = state.get("shape_verdict")
    if verdict is None:
        prereq.append(item("shape_observation_24h", "UNKNOWN", "no evaluator verdict supplied (earliest 2026-10-24T12:50Z)"))
    else:
        prereq.append(item("shape_observation_24h", "PASS" if verdict.get("status") == "OBSERVED" else "FAIL", f"evaluator status {verdict.get('status')}; it reports measurements only, never a pass"))

    report = {
        "schema": SCHEMA,
        "generated_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "live_ready": False,
        "reason": "machine checks cannot supply the outstanding human items; this report never declares readiness",
        "gates_closed": gates,
        "prerequisites": prereq,
        "warnings": warnings,
        "outstanding_human_items": OUTSTANDING_HUMAN_ITEMS,
        "summary": {
            "gates_open_or_unknown": [g["id"] for g in gates if g["status"] != "PASS"],
            "prerequisites_failing": [p["id"] for p in prereq if p["status"] == "FAIL"],
            "prerequisites_unknown": [p["id"] for p in prereq if p["status"] == "UNKNOWN"],
        },
    }
    return report


def sh(args, input_text=None, timeout=60):
    return subprocess.run(args, input=input_text, text=True, capture_output=True, timeout=timeout)


def container_env(name, keys):
    out = sh(["docker", "inspect", name, "--format", "{{range .Config.Env}}{{println .}}{{end}}"])
    if out.returncode != 0:
        raise RuntimeError(f"cannot inspect {name}")
    env = dict(line.split("=", 1) for line in out.stdout.splitlines() if "=" in line)
    return {k: env.get(k, "") for k in keys}


QUERY = r"""
BEGIN READ ONLY;
SET LOCAL statement_timeout='20s';
SELECT 'J ' || jsonb_build_object(
 'actions', (SELECT coalesce(jsonb_agg(jsonb_build_object('name', name, 'enabled', enabled)), '[]') FROM actions WHERE name ~ '(block|goaway|quarantine|ratelimit|tailscale|proxmox|docker\.)'),
 'policies', (SELECT coalesce(jsonb_agg(jsonb_build_object('name', name, 'class', class, 'status', status)), '[]') FROM security_policies),
 'runtime', (SELECT coalesce(jsonb_agg(jsonb_build_object('component', component, 'state', state, 'heartbeat_age_seconds', extract(epoch FROM now() - coalesce(last_heartbeat_at, updated_at))::int)), '[]') FROM runtime_status),
 'sensors', (SELECT coalesce(jsonb_agg(jsonb_build_object('name', name, 'age_seconds', extract(epoch FROM now() - last_seen_at)::int)), '[]') FROM security_sensors WHERE enabled AND revoked_at IS NULL),
 'providers', (SELECT coalesce(jsonb_agg(jsonb_build_object('id', p.id, 'enabled', p.enabled, 'interval_seconds', p.interval_seconds, 'state', s.state, 'last_success_age_seconds', extract(epoch FROM now() - s.last_success_at)::int)), '[]') FROM providers p LEFT JOIN provider_status s ON s.provider_id = p.id),
 'orphans', (SELECT coalesce(jsonb_agg(p.proname), '[]') FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'public' AND p.prosecdef AND p.proname LIKE 'clawforge\_%' AND NOT EXISTS (SELECT 1 FROM pg_roles r WHERE r.rolname LIKE 'clawforge\_%' AND has_function_privilege(r.rolname, p.oid, 'EXECUTE')))
)::text;
ROLLBACK;
"""


def collect(args):
    state = {
        "executor_env": container_env("clawforge-clawforge-executor-1", [
            "CLAWFORGE_EXECUTOR_DRY_RUN", "CLAWFORGE_EXECUTOR_LIVE_AUTHORIZATION", "CLAWFORGE_FIREWALL_NEVER_BLOCK_CIDRS",
            "CLAWFORGE_FIREWALL_MAX_TTL_SECONDS", "CLAWFORGE_FIREWALL_MAX_APPLIES_PER_WINDOW", "CLAWFORGE_FIREWALL_RATE_WINDOW_SECONDS",
            "CLAWFORGE_FIREWALL_MAX_CONCURRENT_APPLIES_PER_ADAPTER"]),
        "policy_engine_env": container_env("clawforge-clawforge-policy-engine-1", ["CLAWFORGE_POLICY_BRIDGE_MODE", "CLAWFORGE_POLICY_BRIDGE_MAX_EVIDENCE_AGE_SECONDS"]),
        "worker_env": container_env("clawforge-clawforge-worker-1", ["CLAWFORGE_ENABLE_IP_CONTEXT"]),
    }
    result = sh(["docker", "exec", "-i", "clawforge-postgres-1", "psql", "-X", "-At", "-U", "clawforge", "-d", "clawforge", "-v", "ON_ERROR_STOP=1"], QUERY)
    lines = [l for l in result.stdout.splitlines() if l.startswith("J ")]
    if result.returncode != 0 or len(lines) != 1:
        raise RuntimeError("database collector failed: " + result.stderr.strip()[:200])
    data = json.loads(lines[0][2:])
    state.update(actions=data["actions"], policies=data["policies"], runtime=data["runtime"], sensors=data["sensors"],
                 providers=data["providers"], orphan_security_definer_functions=data["orphans"])
    state["backup"] = None
    if args.backup_dir:
        try:
            files = [f for f in os.scandir(args.backup_dir) if f.is_file() and f.name.endswith(".dump")]
            newest = max(files, key=lambda f: f.stat().st_mtime, default=None)
            usage = os.statvfs(args.backup_dir)
            state["backup"] = {"files": len(files), "newest_age_seconds": int(dt.datetime.now().timestamp() - newest.stat().st_mtime) if newest else None,
                               "newest_bytes": newest.stat().st_size if newest else None, "free_gib": usage.f_bavail * usage.f_frsize / 2**30, "retention_days": 14}
        except OSError:
            state["backup"] = None
    if args.shape_verdict:
        with open(args.shape_verdict, encoding="utf-8") as handle:
            state["shape_verdict"] = json.load(handle)
    return state


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--shape-verdict")
    parser.add_argument("--backup-dir")
    parser.add_argument("--collected-fixture")
    parser.add_argument("--out")
    args = parser.parse_args(argv)
    now = dt.datetime.now(dt.timezone.utc)
    try:
        if args.collected_fixture:
            with open(args.collected_fixture, encoding="utf-8") as handle:
                state = json.load(handle)
        else:
            state = collect(args)
        report = evaluate(state, now)
    except (RuntimeError, OSError, ValueError, KeyError, subprocess.TimeoutExpired) as error:
        print(json.dumps({"schema": SCHEMA, "status": "ERROR", "error": str(error), "live_ready": False}))
        return 2
    text = json.dumps(report, indent=2, sort_keys=True)
    print(text)
    if args.out:
        fd = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
