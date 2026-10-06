#!/usr/bin/env python3
"""Run the Rust adapter against disposable loopback HTTPS, never a live PVE.

Requires Python 3, OpenSSL and Cargo. Certificates, keys and server are removed
on completion. Run from any directory; optional --evidence saves safe counters.
"""
import argparse
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import ssl
import subprocess
import tempfile
import threading
from urllib.parse import parse_qs, unquote


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    original = "virtio=BC:24:11:6D:2B:EF,bridge=vmbr0,firewall=1,tag=12,link_down=0"
    isolated = original.replace(",link_down=0", ",link_down=1")
    states = {vm: original for vm in range(9001, 9013)}
    revisions = Counter()
    reads = Counter()
    writes = Counter()
    events = []
    failures = []
    logins = 0
    tasks = {}
    task_reads = Counter()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def respond(self, status, data):
            body = json.dumps({"data": data}).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def vm(self):
            prefix = "/api2/json/nodes/lab/qemu/"
            if not self.path.startswith(prefix) or not self.path.endswith("/config"):
                raise AssertionError("unexpected fixture endpoint")
            vm = int(self.path[len(prefix):].split("/")[0])
            assert vm in states
            assert self.headers.get("Cookie") == "PVEAuthCookie=mock-ticket"
            return vm

        def do_GET(self):
            try:
                if self.path.startswith("/api2/json/nodes/lab/tasks/"):
                    assert self.headers.get("Cookie") == "PVEAuthCookie=mock-ticket"
                    assert self.path.endswith("/status")
                    encoded = self.path.removeprefix("/api2/json/nodes/lab/tasks/").removesuffix("/status")
                    assert "/" not in encoded and "?" not in encoded
                    upid = unquote(encoded)
                    vm, value = tasks[upid]
                    task_reads[upid] += 1
                    events.append(["task-status", vm])
                    if task_reads[upid] == 1 or vm == 9009:
                        self.respond(200, {"status": "running"})
                    elif vm == 9008:
                        self.respond(200, {"status": "stopped", "exitstatus": "ERROR: fixture task failed"})
                    else:
                        if vm != 9002 or value != original:
                            states[vm] = value
                            revisions[vm] += 1
                        self.respond(200, {"status": "stopped", "exitstatus": "OK"})
                    return
                vm = self.vm()
                reads[vm] += 1
                if vm == 9003 and reads[vm] == 3:
                    states[vm] = isolated + ",rate=operator-drift"
                    revisions[vm] += 1
                data = {"net0": states[vm], "digest": f"digest-{revisions[vm]}"}
                if vm == 9004:
                    data["net1"] = original
                if vm == 9005:
                    del data["digest"]
                events.append(["read", vm])
                self.respond(200, data)
            except Exception as error:
                failures.append(str(error))
                self.respond(400, None)

        def do_POST(self):
            nonlocal logins
            try:
                form = parse_qs(self.rfile.read(int(self.headers["Content-Length"])).decode())
                if self.path == "/api2/json/access/ticket":
                    assert form == {"username": ["mock@pam"], "password": ["mock-only"]}
                    logins += 1
                    events.append(["login"])
                    self.respond(200, {"ticket": "mock-ticket", "CSRFPreventionToken": "mock-csrf"})
                    return
                vm = self.vm()
                assert self.headers.get("CSRFPreventionToken") == "mock-csrf"
                assert set(form) == {"net0", "digest"}
                writes[vm] += 1
                if vm == 9006:
                    revisions[vm] += 1  # concurrent config change after read
                if form["digest"] != [f"digest-{revisions[vm]}"]:
                    events.append(["cas-conflict", vm])
                    self.respond(409, None)
                    return
                assert form["net0"][0] in (original, isolated)
                events.append(["write", vm])
                if vm == 9010:
                    self.respond(200, None)  # POST without background_delay must return a task
                elif vm == 9011:
                    self.respond(200, "UPID:lab:1:1:1:qmconfig:9011:mock@pam:/../inject?")
                elif vm == 9012:
                    self.respond(200, "UPID:lab:1:1:1:qmconfig:9001:mock@pam:")
                else:
                    upid = f"UPID:lab:{len(tasks)+1:08x}:00000001:00000001:qmconfig:{vm}:mock@pam:"
                    tasks[upid] = (vm, form["net0"][0])
                    self.respond(200, upid)
            except Exception as error:
                failures.append(str(error))
                self.respond(400, None)

    with tempfile.TemporaryDirectory(prefix="clawforge-proxmox-https-") as directory:
        path = Path(directory)

        def openssl(*arguments):
            subprocess.run(["openssl", *arguments], cwd=path, check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        for name in ("ca", "wrong-ca"):
            openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                    "-subj", f"/CN=Clawforge test {name}", "-keyout", f"{name}.key",
                    "-out", f"{name}.pem", "-addext", "basicConstraints=critical,CA:TRUE")
        openssl("req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj",
                "/CN=Clawforge loopback fixture", "-keyout", "server.key", "-out", "server.csr")
        (path / "server.ext").write_text(
            "subjectAltName=IP:127.0.0.1\nbasicConstraints=critical,CA:FALSE\n"
            "keyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n")
        openssl("x509", "-req", "-in", "server.csr", "-CA", "ca.pem", "-CAkey", "ca.key",
                "-CAcreateserial", "-out", "server.pem", "-days", "1", "-extfile", "server.ext")
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(path / "server.pem", path / "server.key")
        server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        env = os.environ.copy()
        env.update({
            "CLAWFORGE_PROXMOX_HTTPS_MOCK_HOST": f"127.0.0.1:{server.server_port}",
            "CLAWFORGE_PROXMOX_HTTPS_MOCK_CA_FILE": str(path / "ca.pem"),
            "CLAWFORGE_PROXMOX_CA_FILE": str(path / "ca.pem"),
            "CLAWFORGE_PROXMOX_HTTPS_MOCK_WRONG_CA_FILE": str(path / "wrong-ca.pem"),
            "NO_PROXY": "127.0.0.1,localhost",
            "no_proxy": "127.0.0.1,localhost",
        })
        try:
            result = subprocess.run([
                "cargo", "test", "-p", "clawforge-firewall-agent",
                "proxmox::tests::https_mock_confirms_tls_cas_and_rollback_readback_fail_closed",
                "--", "--ignored", "--exact", "--nocapture",
            ], cwd=root, env=env, check=False)
        finally:
            server.shutdown()
            server.server_close()
            thread.join()
        assert result.returncode == 0, "Rust HTTPS test failed"
        assert not failures, failures
        assert writes == Counter({9001: 2, 9002: 2, 9003: 1, 9006: 1,
                                  9008: 1, 9009: 1, 9010: 1, 9011: 1, 9012: 1}), dict(writes)
        assert reads[9001] == 10, "prepared drift rejection plus exact rollback readback and idempotence required"
        assert states[9001] == original
        assert states[9002] == isolated, "false success retained NIC must be detected"
        assert states[9003] == isolated + ",rate=operator-drift"
        assert all(states[vm] == original for vm in (9004, 9005, 9006, 9007, 9008, 9009, 9010, 9011, 9012))
        assert len(tasks) == 7
        assert all(count == 2 for upid, count in task_reads.items() if ":9009:" not in upid)
        assert any(count > 1 for upid, count in task_reads.items() if ":9009:" in upid)
        assert events[0] == ["login"] and events[1] == ["read", 9001]
        # Three rejected TLS handshakes must deliver no credentials to HTTP.
        assert logins == 25, f"unexpected credential POST count: {logins}"
        evidence = {"result": "passed", "loopback_only": True,
                    "live_pve_test": "not performed; network blocked in previous verified probe",
                    "credential_posts": logins, "config_reads": dict(reads),
                    "config_write_attempts": dict(writes), "events": events,
                    "checks": ["trusted CA", "untrusted CA", "wrong CA", "wrong server name",
                               "digest CAS", "CAS conflict", "exact rollback", "rollback readback",
                               "idempotent rollback", "operator drift", "multi-NIC",
                               "missing digest", "dry run", "async running then OK",
                               "async failure", "async timeout", "missing UPID",
                               "UPID path injection rejected", "task VM binding"],
                    "temporary_server_and_key_cleanup": True}
    if args.evidence:
        args.evidence.parent.mkdir(parents=True, exist_ok=True)
        args.evidence.write_text(json.dumps(evidence, indent=2) + "\n")
        args.evidence.chmod(0o600)
    print(json.dumps({key: value for key, value in evidence.items() if key != "events"}))


if __name__ == "__main__":
    main()
