import importlib.util
import json
from pathlib import Path
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('adapter', ROOT / 'sensors/network-ids/eve_adapter.py')
a = importlib.util.module_from_spec(spec)
spec.loader.exec_module(a)


def alert(**changes):
    row = dict(timestamp='2026-10-21T20:00:00.000001+0000', event_type='alert',
               src_ip='203.0.113.8', dest_ip='198.51.100.10', src_port=41000,
               dest_port=80, proto='TCP', flow_id=123456789123456789,
               alert=dict(signature_id=1000001, gid=1, rev=1, severity=2, action='allowed'),
               payload='secret', http={'authorization': 'Bearer secret'},
               metadata={'private': 'secret'})
    row.update(changes)
    return row


def line(row):
    return json.dumps(row).encode() + b'\n'


class AdapterTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.eve = self.root / 'eve.json'
        self.eve.touch()
        self.db = a.connect(self.root / 'state.db')
        self.addCleanup(self.db.close)

    def read(self):
        return a.read_step(self.db, self.eve, 'suricata:lab')

    def pending(self):
        return [json.loads(r[0]) for r in self.db.execute('SELECT event FROM pending ORDER BY seq')]

    def test_allowlist_and_not_attacker_attribution(self):
        out = a.normalize(line(alert()), 'suricata:lab')
        self.assertEqual(out['event_type'], 'network_ids_alert')
        self.assertEqual(out['source_ip'], '203.0.113.8')
        self.assertEqual(out['observed_action'], 'allowed')
        self.assertNotIn('secret', json.dumps(out))
        self.assertNotIn('attacker', out)
        changed = alert(payload='different', metadata={'bad': 'data'})
        self.assertEqual(out, a.normalize(line(changed), 'suricata:lab'))

    def test_ipv6_and_high_precision_flow_id(self):
        out = a.normalize(line(alert(src_ip='2001:db8::1', proto='ICMPv6')), 'suricata:lab')
        self.assertEqual(out['protocol'], 'icmpv6')
        self.assertEqual(out['flow_id'], 123456789123456789)

    def test_unknown_event_ignored(self):
        for event in ('stats', 'dns', 'http', 'flow', 'anomaly', 'future'):
            self.assertIsNone(a.normalize(line(dict(event_type=event)), 'suricata:lab'))

    def test_invalid_fields_rejected(self):
        bad = [dict(src_ip='not-ip'), dict(src_port=65536), dict(flow_id=True),
               dict(timestamp='2026-10-21T12:00:00'), dict(alert=[]),
               dict(alert={'severity': 0}), dict(proto=None)]
        for change in bad:
            with self.subTest(change=change), self.assertRaises((ValueError, KeyError, AttributeError, TypeError)):
                a.normalize(line(alert(**change)), 'suricata:lab')

    def test_dedupe_preserves_distinct_transactions(self):
        one = a.normalize(line(alert(tx_id=1)), 'suricata:lab')
        two = a.normalize(line(alert(tx_id=2)), 'suricata:lab')
        self.assertNotEqual(one['dedupe_key'], two['dedupe_key'])
        self.assertEqual(one, a.normalize(line(alert(tx_id=1)), 'suricata:lab'))

    def test_partial_line_waits_then_completes(self):
        raw = line(alert())
        self.eve.write_bytes(raw[:-1])
        self.assertFalse(self.read())
        self.assertEqual(self.pending(), [])
        with self.eve.open('ab') as f:
            f.write(b'\n')
        self.assertTrue(self.read())
        self.assertEqual(len(self.pending()), 1)

    def test_restart_and_pending_survive(self):
        self.eve.write_bytes(line(alert()))
        self.read()
        self.db.close()
        self.db = a.connect(self.root / 'state.db')
        self.addCleanup(self.db.close)
        self.assertFalse(self.read())
        self.assertEqual(len(self.pending()), 1)

    def test_rotation_drains_old_inode(self):
        self.eve.write_bytes(line(alert()))
        self.read()
        old = self.root / 'eve.json.1'
        self.eve.rename(old)
        with old.open('ab') as f:
            f.write(line(alert(tx_id=2)))
        self.eve.write_bytes(line(alert(tx_id=3)))
        self.assertTrue(self.read())  # old unread tail
        self.assertTrue(self.read())  # switch cursor at EOF
        self.assertTrue(self.read())  # new inode
        self.assertFalse(self.read())
        self.assertEqual(len(self.pending()), 3)

    def test_truncation_and_rewrite_fail_without_losing_pending(self):
        self.eve.write_bytes(line(alert()))
        self.read()
        self.eve.write_bytes(line(alert(src_ip='203.0.113.9')))
        with self.assertRaisesRegex(RuntimeError, 'rewritten'):
            self.read()
        self.assertEqual(len(self.pending()), 1)
        self.eve.write_bytes(b'')
        with self.assertRaisesRegex(RuntimeError, 'truncated'):
            self.read()

    def test_missing_rotation_is_reported(self):
        self.eve.write_bytes(line(alert()))
        self.read()
        self.eve.rename(self.root / 'old')
        (self.root / 'old').unlink()
        self.eve.write_bytes(line(alert()))
        with self.assertRaisesRegex(RuntimeError, 'input gap'):
            self.read()

    def test_malformed_counted_without_payload_logging(self):
        self.eve.write_bytes(b'not json secret\n' + line(alert()))
        self.assertTrue(self.read())
        self.assertTrue(self.read())
        self.assertEqual(dict(self.db.execute('SELECT name,value FROM counters')), {'invalid': 1, 'queued': 1})

    def test_oversize_stops_before_advancing(self):
        self.eve.write_bytes(b'x' * (a.MAX_LINE + 1) + b'\n')
        with self.assertRaisesRegex(RuntimeError, 'oversized'):
            self.read()
        self.assertIsNone(self.db.execute('SELECT * FROM cursor').fetchone())

    def test_backpressure_keeps_unread_input(self):
        self.eve.write_bytes(line(alert()))
        self.db.executemany('INSERT INTO pending(event) VALUES (?)', [('{}',)] * a.MAX_PENDING)
        self.db.commit()
        self.assertFalse(self.read())
        self.assertIsNone(self.db.execute('SELECT * FROM cursor').fetchone())

    def server(self, mode):
        seen = []
        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                seen.append((self.headers['Authorization'], json.loads(self.rfile.read(int(self.headers['Content-Length'])))))
                if mode == 'redirect':
                    self.send_response(302)
                    self.send_header('Location', '/stolen')
                    self.end_headers()
                    return
                if mode == 'rate':
                    self.send_response(429)
                    self.send_header('Retry-After', '20')
                    self.end_headers()
                    return
                items = [{'status': 'accepted'} for _ in seen[-1][1]]
                if mode == 'reject':
                    items[-1]['status'] = 'rejected'
                if mode == 'short':
                    items = []
                body = json.dumps({'data': {'results': items}}).encode()
                self.send_response(200)
                self.end_headers()
                self.wfile.write(body)
            def log_message(self, *args):
                pass
        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return 'http://127.0.0.1:%s/internal/security-events/batch' % server.server_port, seen

    def test_http_failure_rejection_and_redirect_retain_outbox(self):
        self.eve.write_bytes(line(alert()))
        self.read()
        for mode in ('reject', 'short', 'rate', 'redirect'):
            url, seen = self.server(mode)
            with self.subTest(mode=mode), self.assertRaises(Exception):
                a.send_step(self.db, url, 'test-token')
            self.assertEqual(len(self.pending()), 1)
            self.assertEqual(len(seen), 1)

    def test_send_is_bounded_and_restart_retry_deduplicable(self):
        row = a.normalize(line(alert()), 'suricata:lab')
        self.db.executemany('INSERT INTO pending(event) VALUES (?)', [(json.dumps(row),)] * 51)
        self.db.commit()
        url, seen = self.server('accept')
        self.assertTrue(a.send_step(self.db, url, 'test-token'))
        self.assertEqual(len(self.pending()), 1)
        self.assertEqual(len(seen[0][1]), 50)
        self.assertEqual(seen[0][0], 'Bearer test-token')
        self.assertTrue(a.send_step(self.db, url, 'test-token'))
        self.assertEqual(len(self.pending()), 0)

    def test_rate_limit_retry_after_is_respected(self):
        import urllib.error
        from email.message import Message
        headers = Message()
        headers['Retry-After'] = '90'
        error = urllib.error.HTTPError('http://local', 429, 'rate', headers, None)
        self.assertEqual(a.retry_after(error), 90)
        headers.replace_header('Retry-After', '99999')
        self.assertEqual(a.retry_after(error), 3600)

    def test_endpoint_rejects_credentials_and_unapproved_plaintext(self):
        for url in ('http://remote:8080', 'https://user:password@server',
                    'https://server/?secret=1', 'file:///tmp/api'):
            with self.subTest(url=url), self.assertRaises(ValueError):
                a.endpoint(url, False)
        self.assertEqual(a.endpoint('http://127.0.0.1:8080', False),
                         'http://127.0.0.1:8080/internal/security-events/batch')


if __name__ == '__main__':
    unittest.main()
