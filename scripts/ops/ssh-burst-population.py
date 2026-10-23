#!/usr/bin/env python3
"""Aggregate-only measurement of the SSH failure population on a sensor host (run as root there).

Reads the sshd journal of the last N days (default 7) and prints COUNTS only: never an address, account
name or path. It answers what the detector's raw alerts would be made of in reality:
  * how many failure sources ever logged in successfully (does a "successful login from the same source"
    signal have any population to separate?),
  * how the sources with a burst (>= 5 failures within 300 s, the five-minute rule) split into
    enumeration (>= 8 names), the invalid_account_probe shape (>= 4 nonexistent names), a single existing
    account, and the rest.
A frequency is not a false-positive rate: this host has no labelled legitimate bursts.
  python3 ssh-burst-population.py [days]
"""
import collections, datetime as dt, re, subprocess, sys

days = int(sys.argv[1]) if len(sys.argv) > 1 else 7
out = subprocess.run(["journalctl", "-u", "ssh", "-u", "sshd", "--since", f"-{days}days", "--no-pager", "-o", "short-iso"],
                     capture_output=True, text=True).stdout
fail = re.compile(r"Failed \w+ for (invalid user )?(\S+) from (\S+)|Invalid user (\S+) from (\S+)")
acc = re.compile(r"Accepted \w+ for \S+ from (\S+)")
ev = collections.defaultdict(list)
accepted_sources = set()
for line in out.splitlines():
    head = line.split(None, 1)[0]
    if not head[:4].isdigit():
        continue
    ts = dt.datetime.fromisoformat(head.replace("Z", "+00:00")).timestamp()
    m = fail.search(line)
    if m:
        if m.group(4):
            ev[m.group(5)].append((ts, m.group(4).lower(), True))
        else:
            ev[m.group(3)].append((ts, m.group(2).lower(), bool(m.group(1))))
        continue
    m = acc.search(line)
    if m:
        accepted_sources.add(m.group(1))

failure_sources = set(ev)
print(f"window: {days} days | sources with failures: {len(failure_sources)} | "
      f"of those that ever had an accepted login: {len(failure_sources & accepted_sources)} | "
      f"sources that only ever logged in: {len(accepted_sources - failure_sources)}")
classes, sizes, bursts = collections.Counter(), collections.defaultdict(list), 0
for ip, v in ev.items():
    v.sort()
    t = [x[0] for x in v]
    b = next((i for i in range(len(t) - 4) if t[i + 4] - t[i] <= 300), None)
    if b is None:
        continue
    bursts += 1
    j = b + 4
    while j + 1 < len(t) and t[j + 1] - t[j] <= 300:
        j += 1
    window = v[b:j + 1]
    names = {n for _, n, _ in window}
    invalid = {n for _, n, i in window if i}
    if len(names) >= 8:
        kind = "enumeration (>= 8 names)"
    elif len(invalid) >= 4:
        kind = "invalid_account_probe (>= 4 nonexistent names, < 8 total)"
    elif len(names) == 1 and not invalid:
        kind = "one existing account only"
    elif len(names) == 1:
        kind = "one nonexistent account only"
    elif not invalid:
        kind = "several existing accounts, none nonexistent"
    else:
        kind = "mixed, below both thresholds"
    classes[kind] += 1
    sizes[kind].append(len(window))
print(f"burst sources (>= 5 failures in 300 s): {bursts}")
for kind, n in classes.most_common():
    s = sorted(sizes[kind])
    print(f"  {n:5d}  {kind}  (attempts in window: median {s[len(s) // 2]}, max {s[-1]})")
