#!/usr/bin/env python3
"""Aggregate-only measurement of the HTTP error population in HAProxy httplog files (run as root on the
sensor host). Prints COUNTS only (never an address or path): how many sources produce >= 8 error responses
within 300 s and what share of their responses in that window were successes (< 400). A success ratio can
only separate a legitimate burst (a browser with a broken asset release still receives pages) from a
scanner (almost only errors) if legitimate bursts exist in the data; this reports whether they do.
  python3 http-burst-population.py [/var/log/haproxy.log*]
"""
import collections, datetime as dt, glob, gzip, re, sys

client = re.compile(r" (\S+?):\d+ \[(\d+/\w+/\d+:\d+:\d+:\d+)\.\d+\] ")
status = re.compile(r" \d+/\d+/\d+/\d+/\d+ (\d{3}) ")
months = {m: i for i, m in enumerate("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split(), 1)}
paths = sys.argv[1:] or sorted(glob.glob("/var/log/haproxy.log*"))
ev, total = collections.defaultdict(list), 0
for path in paths:
    opener = gzip.open if path.endswith(".gz") else open
    with opener(path, "rt", errors="replace") as handle:
        for line in handle:
            a, b = client.search(line), status.search(line)
            if not a or not b:
                continue
            day, mon, rest = a.group(2).split("/", 2)
            y, h, m, s = rest.split(":")
            ts = dt.datetime(int(y), months[mon], int(day), int(h), int(m), int(s), tzinfo=dt.timezone.utc).timestamp()
            ev[a.group(1)].append((ts, int(b.group(1))))
            total += 1
print(f"requests parsed: {total} | distinct sources: {len(ev)}")
classes = collections.Counter()
for v in ev.values():
    v.sort()
    errors = [t for t, s in v if s >= 400]
    k = next((i for i in range(len(errors) - 7) if errors[i + 7] - errors[i] <= 300), None)
    if k is None:
        continue
    window = [s for t, s in v if errors[k] <= t <= errors[k + 7]]
    ok = sum(1 for s in window if s < 400)
    classes["all errors" if ok == 0 else ("mostly errors (< 50% success)" if ok / len(window) < 0.5 else "mostly successes (>= 50%)")] += 1
print(f"sources with >= 8 error responses in 300 s: {sum(classes.values())}")
for kind, n in classes.most_common():
    print(f"  {n:5d}  {kind}")
