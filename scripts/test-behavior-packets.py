#!/usr/bin/env python3
"""Build as the caller; run only the packet test in a fresh root network namespace."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--report-dir', required=True, type=Path)
p.add_argument('--run-isolated-lab', required=True, action='store_true')
a = p.parse_args()
repo = Path(__file__).resolve().parents[1]
out = a.report_dir.resolve()
out.mkdir(parents=True, exist_ok=True)
command = [shutil.which('cargo') or 'cargo', 'test', '--offline', '--locked', '-p',
           'clawforge-firewall-agent', '--test', 'behavior_packet_lab', '--no-run', '--message-format=json']
result = subprocess.run(command, cwd=repo, check=True, capture_output=True, text=True, timeout=600)
artifacts = [json.loads(line) for line in result.stdout.splitlines() if line.startswith('{')]
executables = [r['executable'] for r in artifacts if r.get('executable') and
               r.get('target', {}).get('name') == 'behavior_packet_lab']
assert len(executables) == 1
parent = os.readlink('/proc/self/ns/net')
args = ['sudo', '-n', 'unshare', '--net', '--', '/usr/bin/env', 'PATH=/usr/sbin:/usr/bin:/sbin:/bin',
        'CLAWFORGE_BEHAVIOR_HOST_NETNS=' + parent, 'CLAWFORGE_BEHAVIOR_REPORT_DIR=' + str(out),
        executables[0], 'isolated_adapter_packets_ttl_and_rollback', '--ignored', '--nocapture']
with (out / 'packet-test.log').open('w') as stream:
    subprocess.run(args, stdout=stream, stderr=subprocess.STDOUT, check=True, timeout=90)
report = json.loads((out / 'packet-report.json').read_text())
assert report['same_namespace'] is False and report['ttl_samples'] == 8
print(json.dumps({'passed': True, 'ttl_samples': report['ttl_samples'],
                  'private_namespace': report['test_namespace'], 'report': str(out / 'packet-report.json')}))
