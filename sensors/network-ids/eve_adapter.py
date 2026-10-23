#!/usr/bin/env python3
"""Clawforge-owned passive EVE adapter. Python standard library only.

Network access is exclusively to the configured authenticated ingress. Reads
existing logs; never starts capture, executes rules, or changes a firewall.
"""
import argparse
import datetime as dt
import fcntl
import email.utils
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import sqlite3
import time
import urllib.error
import urllib.parse
import urllib.request

MAX_LINE = 262144
MAX_PENDING = 10000
HEARTBEAT_EVERY = 60       # seconds between heartbeats while the engine is demonstrably alive
STATS_FRESH_WITHIN = 150   # the engine writes stats every 30 s; five missed intervals = not alive
STATUS_EVERY = 30


def integer(value, name, maximum=2**64 - 1):
    if type(value) is not int or not 0 <= value <= maximum:
        raise ValueError(name)
    return value


def normalize(raw, source):
    """Allowlist fields; no signature text, metadata or payload ever forwarded."""
    row = json.loads(raw)
    if not isinstance(row, dict):
        raise ValueError('object required')
    if row.get('event_type') != 'alert':
        return None
    alert = row['alert']
    if not isinstance(alert, dict):
        raise ValueError('alert object required')
    stamp = dt.datetime.fromisoformat(row['timestamp'].replace('Z', '+00:00'))
    if stamp.utcoffset() is None:
        raise ValueError('timestamp timezone required')
    stamp = stamp.astimezone(dt.timezone.utc).isoformat()
    src = str(ipaddress.ip_address(row['src_ip']))
    dst = str(ipaddress.ip_address(row['dest_ip']))
    sev = integer(alert['severity'], 'severity', 4)
    if sev == 0:
        raise ValueError('severity')
    proto = row['proto'].lower()
    if proto not in ('tcp', 'udp', 'icmp', 'icmpv6', 'sctp'):
        proto = 'other'
    action = alert.get('action', 'unknown')
    if action not in ('allowed', 'blocked'):
        action = 'unknown'
    event = dict(event_type='network_ids_alert', occurred_at=stamp, source=source,
                 severity={1: 'high', 2: 'medium', 3: 'low', 4: 'info'}[sev],
                 resource=src, source_ip=src, destination_ip=dst,
                 source_port=None, destination_port=None, protocol=proto,
                 engine='suricata', signature_id=integer(alert['signature_id'], 'sid', 2**32-1),
                 generator_id=integer(alert.get('gid', 1), 'gid', 2**32-1),
                 signature_revision=integer(alert.get('rev', 0), 'rev', 2**32-1),
                 native_severity=sev, observed_action=action, flow_id=None)
    for key, output, limit in (('src_port', 'source_port', 65535),
                               ('dest_port', 'destination_port', 65535),
                               ('flow_id', 'flow_id', 2**64-1)):
        if key in row:
            event[output] = integer(row[key], key, limit)
    # Additional identity fields distinguish transactions/packets, but are not
    # exposed as evidence. Mutable/disallowed metadata cannot change identity.
    identity = dict(event)
    for key in ('tx_id', 'pcap_cnt'):
        if key in row:
            identity[key] = integer(row[key], key)
    digest = hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()
    event['dedupe_key'] = 'eve:' + digest
    return event


def engine_stats(raw):
    """Capture counters of an EVE `stats` record: (record time, kernel_packets, kernel_drops) or
    None. Numbers only; anything unexpected is ignored rather than trusted."""
    if b'"stats"' not in raw:
        return None
    try:
        row = json.loads(raw)
        if not isinstance(row, dict) or row.get('event_type') != 'stats':
            return None
        capture = row['stats']['capture']
        stamp = dt.datetime.fromisoformat(row['timestamp'].replace('Z', '+00:00'))
        if stamp.utcoffset() is None:
            return None
        return (stamp.astimezone(dt.timezone.utc).timestamp(),
                integer(capture['kernel_packets'], 'kernel_packets'),
                integer(capture['kernel_drops'], 'kernel_drops'))
    except (ValueError, KeyError, TypeError, AttributeError, OverflowError):
        return None


def connect(path):
    db = sqlite3.connect(path)
    db.execute('PRAGMA journal_mode=WAL')
    db.execute('PRAGMA synchronous=FULL')
    db.executescript('''
        CREATE TABLE IF NOT EXISTS cursor (id INTEGER PRIMARY KEY CHECK(id=1),
          device INTEGER, inode INTEGER, offset INTEGER, anchor TEXT);
        CREATE TABLE IF NOT EXISTS pending (seq INTEGER PRIMARY KEY,
          event TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS counters (name TEXT PRIMARY KEY, value INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS engine (id INTEGER PRIMARY KEY CHECK(id=1),
          stats_at REAL NOT NULL, packets INTEGER NOT NULL, drops INTEGER NOT NULL);
    ''')
    return db


def count(db, name, amount=1):
    db.execute('INSERT INTO counters VALUES (?,?) ON CONFLICT(name) DO UPDATE SET value=value+excluded.value',
               (name, amount))


def anchor(stream, offset):
    stream.seek(0)
    head = stream.read(min(128, offset))
    stream.seek(max(0, offset-128))
    result = hashlib.sha256(head + stream.read(min(128, offset))).hexdigest()
    stream.seek(offset)
    return result


def read_step(db, path, source):
    """Atomic cursor + outbox. Rotation drained, truncation/gaps fail loudly."""
    state = db.execute('SELECT device,inode,offset,anchor FROM cursor WHERE id=1').fetchone()
    current = path.stat()
    selected = path
    offset = 0
    if state:
        dev, ino, offset, expected = state
        if (dev, ino) != (current.st_dev, current.st_ino):
            matches = [p for p in path.parent.iterdir()
                       if p.is_file() and (p.stat().st_dev, p.stat().st_ino) == (dev, ino)]
            if not matches:
                raise RuntimeError('previous EVE inode missing; input gap requires operator review')
            selected = matches[0]
    with selected.open('rb') as stream:
        st = os.fstat(stream.fileno())
        if state and (st.st_dev, st.st_ino) == state[:2]:
            if st.st_size < offset or anchor(stream, offset) != state[3]:
                raise RuntimeError('EVE input truncated or rewritten; operator review required')
        else:
            stream.seek(offset)
        if db.execute('SELECT count(*) FROM pending').fetchone()[0] >= MAX_PENDING:
            return False  # leave unread bytes on disk, never drop for backpressure
        raw = stream.readline(MAX_LINE + 1)
        if len(raw) > MAX_LINE:
            raise RuntimeError('oversized EVE line; cursor retained for operator review')
        if not raw:
            if selected != path:
                # Old inode fully drained; move to new file in one transaction.
                with db:
                    db.execute('INSERT OR REPLACE INTO cursor VALUES (1,?,?,0,?)',
                               (current.st_dev, current.st_ino, hashlib.sha256(b'').hexdigest()))
                return True
            return False
        if not raw.endswith(b'\n'):
            if selected != path:
                raise RuntimeError('partial EVE line in rotated file; operator review required')
            return False  # writer has not completed its JSON line yet
        end = stream.tell()
        try:
            event = normalize(raw, source)
        except (ValueError, KeyError, TypeError, AttributeError, OverflowError):
            # Count rejection and advance atomically. Never log the raw line.
            event = None
            outcome = 'invalid'
        else:
            outcome = 'queued' if event else 'ignored'
        digest = anchor(stream, end)
        stats = engine_stats(raw) if outcome == 'ignored' else None
        with db:
            if stats:
                db.execute('INSERT OR REPLACE INTO engine VALUES (1,?,?,?)', stats)
                count(db, 'engine_stats')
            if event:
                db.execute('INSERT INTO pending(event) VALUES (?)', (json.dumps(event),))
            count(db, outcome)
            db.execute('INSERT OR REPLACE INTO cursor VALUES (1,?,?,?,?)',
                       (st.st_dev, st.st_ino, end, digest))
    return True


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def endpoint(url, allow_http):
    parsed = urllib.parse.urlsplit(url)
    if (parsed.scheme not in ('http', 'https') or not parsed.hostname
            or parsed.username or parsed.password or parsed.query or parsed.fragment):
        raise ValueError('invalid ingress URL')
    if parsed.scheme != 'https' and not allow_http:
        try:
            local = ipaddress.ip_address(parsed.hostname).is_loopback
        except ValueError:
            local = parsed.hostname == 'localhost'
        if not local:
            raise ValueError('remote ingress requires HTTPS; private Docker HTTP needs --allow-http')
    return url.rstrip('/') + '/internal/security-events/batch'


def send_step(db, url, credential):
    rows = db.execute('SELECT seq,event FROM pending ORDER BY seq LIMIT 50').fetchall()
    if not rows:
        return False
    request = urllib.request.Request(url, method='POST',
        data=('[' + ','.join(r[1] for r in rows) + ']').encode(),
        headers={'Content-Type': 'application/json', 'Authorization': 'Bearer ' + credential})
    # Ignore ambient proxy settings; credentials must not reach an unrelated proxy.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    with opener.open(request, timeout=15) as response:
        body = response.read(MAX_LINE + 1)
        if len(body) > MAX_LINE:
            raise RuntimeError('oversized ingress response')
        result = json.loads(body)['data']['results']
        if len(result) != len(rows) or any(r.get('status') != 'accepted' for r in result):
            raise RuntimeError('ingress rejected items; pending events retained')
    with db:
        db.executemany('DELETE FROM pending WHERE seq=?', [(r[0],) for r in rows])
        count(db, 'accepted', len(rows))
    return True


def retry_after(error):
    """Respect 429/503 Retry-After, supporting seconds and HTTP dates."""
    if not isinstance(error, urllib.error.HTTPError) or error.code not in (429, 503):
        return 0
    value = error.headers.get('Retry-After', '')
    try:
        seconds = int(value)
    except ValueError:
        try:
            seconds = int((email.utils.parsedate_to_datetime(value) -
                           dt.datetime.now(dt.timezone.utc)).total_seconds())
        except (TypeError, ValueError, OverflowError):
            return 0
    return min(3600, max(0, seconds))


def engine_state(db, now=None):
    """What the engine last reported: alive = its own newest stats record is recent."""
    now = time.time() if now is None else now
    row = db.execute('SELECT stats_at,packets,drops FROM engine WHERE id=1').fetchone()
    if not row:
        return dict(alive=False, stats_at=None, kernel_packets=None, kernel_drops=None)
    return dict(alive=now - row[0] <= STATS_FRESH_WITHIN,
                stats_at=dt.datetime.fromtimestamp(row[0], dt.timezone.utc).isoformat(),
                kernel_packets=row[1], kernel_drops=row[2])


def heartbeat(base_url, credential):
    """Authenticated liveness ping (refreshes last_seen, creates no event). Only ever sent while
    the engine is alive, so a dead engine shows up as a stale sensor instead of a quiet one."""
    request = urllib.request.Request(base_url.rstrip('/') + '/internal/security-events/heartbeat',
                                     method='POST', data=b'',
                                     headers={'Authorization': 'Bearer ' + credential})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    with opener.open(request, timeout=15) as response:
        response.read(1024)
        return 200 <= response.status < 300


def write_status(path, db, sent_heartbeat_at):
    """Atomic, mode-0600 status file for operators and monitoring (numbers and times only)."""
    counters = dict(db.execute('SELECT name,value FROM counters'))
    counters['pending'] = db.execute('SELECT count(*) FROM pending').fetchone()[0]
    state = engine_state(db)
    status = dict(written_at=dt.datetime.now(dt.timezone.utc).isoformat(), engine=state,
                  adapter=counters, heartbeat_sent_at=sent_heartbeat_at)
    tmp = path.with_name(path.name + '.tmp')
    tmp.write_text(json.dumps(status, sort_keys=True))
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--eve', type=Path, required=True)
    parser.add_argument('--state', type=Path, required=True)
    parser.add_argument('--source', required=True)
    parser.add_argument('--ingress', required=True)
    parser.add_argument('--credential-file', type=Path, required=True)
    parser.add_argument('--allow-http', action='store_true')
    parser.add_argument('--once', action='store_true', help='bounded import; nonzero on any delivery error')
    args = parser.parse_args()
    if not args.source.strip() or len(args.source) > 160:
        parser.error('source must contain 1..160 characters')
    url = endpoint(args.ingress, args.allow_http)
    credential = args.credential_file.read_text().strip()
    if not credential or any(c.isspace() for c in credential):
        parser.error('credential must be a nonempty single token')
    os.umask(0o077)
    args.state.parent.mkdir(parents=True, exist_ok=True)
    with open(str(args.state) + '.lock', 'a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with connect(args.state) as db:
            # Binding prevents accidental reuse under another sensor identity or
            # destination; same file cursor with different semantics would lose data.
            db.execute('CREATE TABLE IF NOT EXISTS binding (id INTEGER PRIMARY KEY, value TEXT)')
            value = json.dumps([str(args.eve.resolve()), args.source, url])
            previous = db.execute('SELECT value FROM binding WHERE id=1').fetchone()
            if previous and previous[0] != value:
                raise RuntimeError('state belongs to another input/source/ingress')
            db.execute('INSERT OR IGNORE INTO binding VALUES (1,?)', (value,))
            db.commit()
            backoff = 1
            base_url = args.ingress
            status_path = args.state.with_name('status.json')
            last_heartbeat = last_status = 0.0
            heartbeat_at = None
            last_drops = None
            while True:
                progressed = False
                for _ in range(100):
                    if not read_step(db, args.eve, args.source):
                        break
                    progressed = True
                try:
                    sent = send_step(db, url, credential)
                except (urllib.error.URLError, TimeoutError, OSError, ValueError, KeyError, TypeError, RuntimeError) as error:
                    with db:
                        count(db, 'send_errors')
                    backoff = max(backoff, retry_after(error))
                    print(json.dumps({'status': 'delivery_failed', 'retry_seconds': backoff}), flush=True)
                    if args.once:
                        return 1
                    time.sleep(backoff)
                    backoff = min(backoff * 2, 60)
                    continue
                backoff = 1
                clock = time.monotonic()
                state = engine_state(db)
                if state['kernel_drops'] is not None and state['kernel_drops'] != last_drops:
                    if last_drops is not None and state['kernel_drops'] > last_drops:
                        print(json.dumps({'status': 'capture_drops',
                                          'new_drops': state['kernel_drops'] - last_drops,
                                          'kernel_packets': state['kernel_packets']}), flush=True)
                    last_drops = state['kernel_drops']
                if not args.once and state['alive'] and clock - last_heartbeat >= HEARTBEAT_EVERY:
                    last_heartbeat = clock
                    try:
                        if heartbeat(base_url, credential):
                            heartbeat_at = dt.datetime.now(dt.timezone.utc).isoformat()
                    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
                        with db:
                            count(db, 'heartbeat_errors')
                if not args.once and clock - last_status >= STATUS_EVERY:
                    last_status = clock
                    write_status(status_path, db, heartbeat_at)
                if args.once and not progressed and not sent:
                    stats = dict(db.execute('SELECT name,value FROM counters'))
                    stats['pending'] = db.execute('SELECT count(*) FROM pending').fetchone()[0]
                    print(json.dumps(stats), flush=True)
                    return 0
                if not progressed and not sent:
                    time.sleep(1)


if __name__ == '__main__':
    raise SystemExit(main())
