#!/usr/bin/env python3
"""Run bounded behavioral acceptance in a new local PostgreSQL fixture only."""
import argparse
import json
import hashlib
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import tempfile
import time
import uuid


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report-dir', type=Path, required=True)
    parser.add_argument('--run-isolated-lab', action='store_true', required=True)
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[1]
    out = args.report_dir.resolve()
    out.mkdir(parents=True, exist_ok=True)
    os.chmod(out, 0o700)
    cargo = shutil.which('cargo')
    if cargo is None:
        raise SystemExit('Rust cargo is required; no automatic toolchain or production changes')
    environment = dict(os.environ)
    environment.update(CLAWFORGE_BEHAVIOR_REPORT_DIR=str(out), CARGO_BUILD_JOBS='2',
                       CLAWFORGE_ANALYZER_IP_HMAC_KEY='isolated-behavior-hmac-key-not-for-production-20261021')
    name = 'clawforge-behavior-' + uuid.uuid4().hex[:12]
    stage = 'startup'
    started = time.time()

    def run(command, *, env=None, timeout=90, input=None):
        return subprocess.run(command, env=env, input=input, text=True, capture_output=True,
                              check=True, timeout=timeout).stdout.strip()

    def rust(log, arguments, timeout=900):
        with (out / log).open('w') as stream:
            subprocess.run([cargo, '--offline', '--locked', *arguments], cwd=repo, env=environment,
                           stdout=stream, stderr=subprocess.STDOUT, check=True, timeout=timeout)

    with tempfile.TemporaryDirectory(prefix='clawforge-behavior-secrets-') as tmp:
        secret_dir = Path(tmp)
        owner_password = secrets.token_urlsafe(24)
        (secret_dir / 'postgres_password').write_text(owner_password)
        role_passwords = {r: secrets.token_urlsafe(24) for r in
                          ['api', 'worker', 'correlation', 'security_engine', 'policy_engine',
                           'incidents', 'executor', 'operations', 'decision', 'backup']}
        for role, password in role_passwords.items():
            (secret_dir / ('database_' + role + '_password')).write_text(password)
        for path in secret_dir.iterdir():
            path.chmod(0o600)
        created = False
        try:
            stage = 'parser_vectors'
            rust('parser-vectors.log', ['test', '-p', 'clawforge-linux-sensor', '-p',
                 'clawforge-haproxy-sensor', 'reviewed_free_model_parser_vectors'])
            stage = 'sensor_exports'
            rust('sensor-exports.log', ['test', '-p', 'clawforge-linux-sensor', '-p',
                 'clawforge-haproxy-sensor', 'export_behavioral_scenarios', '--', '--ignored'])
            stage = 'database_fixture'
            run(['docker', 'run', '--rm', '-d', '--name', name, '--label',
                 'clawforge.test=behavior-validation', '--memory', '512m', '--cpus', '1',
                 '--pids-limit', '128', '-e', 'POSTGRES_DB=clawforge_test', '-e',
                 'POSTGRES_USER=clawforge', '-e', 'POSTGRES_PASSWORD_FILE=/run/test-secrets/postgres_password',
                 '-v', str(secret_dir) + ':/run/test-secrets:ro', '-v',
                 str(repo / 'scripts/provision-db-roles.sh') + ':/provision.sh:ro',
                 '-p', '127.0.0.1::5432', 'postgres:16-alpine'])
            created = True
            deadline = time.monotonic() + 60
            while subprocess.run(['docker', 'exec', name, 'pg_isready', '-h', '127.0.0.1',
                                  '-U', 'clawforge', '-d', 'clawforge_test'], capture_output=True,
                                 timeout=5).returncode:
                if time.monotonic() > deadline:
                    raise RuntimeError('isolated PostgreSQL readiness deadline')
                time.sleep(0.5)
            host_port = run(['docker', 'port', name, '5432/tcp']).split(':')[-1]
            environment['DATABASE_URL'] = f'postgres://clawforge:{owner_password}@127.0.0.1:{host_port}/clawforge_test'
            environment['CLAWFORGE_BEHAVIOR_OWNER_URL'] = environment['DATABASE_URL']
            environment['CLAWFORGE_BEHAVIOR_ENGINE_URL'] = (
                f'postgres://clawforge_security_engine:{role_passwords["security_engine"]}'
                f'@127.0.0.1:{host_port}/clawforge_test')
            stage = 'migrations'
            rust('migrations.log', ['run', '-q', '-p', 'clawforge-storage', '--bin', 'clawforge-migrate'])
            stage = 'least_privilege_roles'
            run(['docker', 'exec', '-e', 'PGHOST=127.0.0.1', '-e', 'POSTGRES_USER=clawforge',
                 '-e', 'POSTGRES_DB=clawforge_test', '-e',
                 'CLAWFORGE_POSTGRES_SECRET_FILE=/run/test-secrets/postgres_password', name,
                 'sh', '-c', 'ln -s /run/test-secrets /run/secrets && sh /provision.sh'])
            stage = 'engine_binary'
            rust('engine-build.log', ['build', '-p', 'clawforge-security-engine'])
            environment['CLAWFORGE_BEHAVIOR_ENGINE_BIN'] = str(Path(environment.get('CARGO_TARGET_DIR', str(repo / 'target'))) / 'debug/clawforge-security-engine')
            stage = 'golden_and_load'
            rust('golden-load.log', ['test', '-p', 'clawforge-security-engine',
                 'golden_behavior_and_bounded_load', '--', '--ignored', '--nocapture'], timeout=300)
            stage = 'ingest_publish_recovery'
            rust('ingest-recovery.log', ['test', '-p', 'clawforge-security-engine',
                 'ingest_publish_interruption_is_recoverable', '--', '--ignored', '--nocapture'], timeout=120)
            stage = 'existing_ingest_regressions'
            rust('existing-ingest-regressions.log', ['test', '-p', 'clawforge-storage', '--test', 'postgres',
                 'security_events_register_sensor_and_record_event', '--', '--ignored', '--exact'], timeout=180)
            rust('existing-reputation-regression.log', ['test', '-p', 'clawforge-storage', '--test', 'postgres',
                 'ip_reputation_lookup_flags_a_match_without_ever_storing_the_raw_ip', '--', '--ignored', '--exact'], timeout=180)
            stage = 'complete'
        finally:
            # Remove only the freshly named, test-labelled container. No shared ports, volumes or pruning.
            cleanup_ok = True
            if created:
                label = run(['docker', 'inspect', '--format',
                             '{{ index .Config.Labels "clawforge.test" }}', name])
                if label != 'behavior-validation':
                    raise RuntimeError('refusing cleanup: unexpected fixture ownership')
                cleanup_ok = subprocess.run(['docker', 'rm', '-f', name], capture_output=True,
                                            timeout=30).returncode == 0
            source_paths = run(['git', '-C', str(repo), 'ls-files', '-co', '--exclude-standard']).splitlines()
            source_manifest = {name: hashlib.sha256((repo / name).read_bytes()).hexdigest() for name in source_paths if (repo / name).is_file() and not name.endswith('.pyc')}
            (out / 'source-manifest.json').write_text(json.dumps(source_manifest, indent=2) + '\n')
            receipt = {'source_tree_sha256': hashlib.sha256(json.dumps(source_manifest, sort_keys=True).encode()).hexdigest(), 'stage': stage, 'finished': stage == 'complete', 'elapsed_seconds': time.time()-started,
                       'fixture_container': name, 'fixture_removed': cleanup_ok,
                       'no_production_changes': True, 'memory_limit_mb': 512, 'cpu_limit': 1,
                       'source_commit': run(['git', '-C', str(repo), 'rev-parse', 'HEAD'])}
            (out / 'runner.json').write_text(json.dumps(receipt, indent=2) + '\n')
            print(json.dumps(receipt), flush=True)


if __name__ == '__main__':
    main()
