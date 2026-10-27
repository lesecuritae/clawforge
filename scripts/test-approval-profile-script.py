#!/usr/bin/env python3
"""Run the real owner configuration script with psql in an isolated PostgreSQL.

No host port, production URL, provider credential or external connection is used.
Requires the postgres:16-alpine image already present (as in the CI PostgreSQL job).
"""
import pathlib
import subprocess
import time
import unittest
import uuid

ROOT = pathlib.Path(__file__).resolve().parents[1]


class ApprovalProfileScript(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.container = None
        name = "clawforge-approval-script-" + uuid.uuid4().hex
        result = subprocess.run(
            ["docker", "run", "--rm", "-d", "--pull", "never", "--network", "none",
             "--name", name, "--tmpfs", "/var/lib/postgresql/data:rw,nosuid,nodev",
             "-e", "POSTGRES_DB=approval_script_fixture", "-e", "POSTGRES_USER=clawforge",
             "-e", "POSTGRES_HOST_AUTH_METHOD=trust", "postgres:16-alpine"],
            capture_output=True, text=True, check=True, timeout=60,
        )
        cls.container = result.stdout.strip()
        cls.addClassCleanup(cls.cleanup)
        deadline = time.monotonic() + 60
        while True:
            ready = subprocess.run(
                ["docker", "exec", cls.container, "pg_isready", "-h", "127.0.0.1",
                 "-U", "clawforge", "-d", "approval_script_fixture"],
                capture_output=True, timeout=10,
            )
            if ready.returncode == 0:
                break
            if time.monotonic() >= deadline:
                raise RuntimeError("isolated PostgreSQL did not become ready")
            time.sleep(0.2)
        schema = "\n".join(p.read_text() for p in sorted((ROOT / "migrations").glob("*.sql")))
        cls.sql(schema)
        cls.sql("INSERT INTO admin_users (id, username, role, password_hash, enabled) "
                "VALUES (gen_random_uuid(), 'approval-script-owner', 'Administrator', '!', TRUE);")

    @classmethod
    def cleanup(cls):
        if cls.container:
            subprocess.run(["docker", "rm", "-f", cls.container], capture_output=True, timeout=30)

    @classmethod
    def psql(cls, source, variables=None, halt=True):
        args = ["docker", "exec", "-i", cls.container, "psql", "-X", "-At",
                "-U", "clawforge", "-d", "approval_script_fixture"]
        if halt:
            args += ["-v", "ON_ERROR_STOP=1"]
        for key, value in (variables or {}).items():
            args += ["-v", key + "=" + value]
        return subprocess.run(args + ["-f", "-"], input=source, text=True,
                              capture_output=True, timeout=90)

    @classmethod
    def sql(cls, source):
        result = cls.psql(source)
        if result.returncode:
            raise AssertionError(result.stderr)
        return result.stdout.strip()

    def setUp(self):
        self.sql("UPDATE approval_profile SET mode='multi_person', operator_user_id=NULL, "
                 "allowed_actions='{}', note='';")

    def configure(self, **variables):
        # Deliberately omit the caller's ON_ERROR_STOP flag: the owner script must enforce it.
        return self.psql((ROOT / "scripts/ops/set-approval-profile.sql").read_text(), variables, halt=False)

    def test_enable_without_optional_note(self):
        result = self.configure(mode="single_operator", operator="approval-script-owner",
                                actions="nftables.block_incident_source")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.sql("SELECT mode FROM approval_profile;"), "single_operator")

    def test_return_to_default_with_only_mode(self):
        self.sql("UPDATE approval_profile SET mode='single_operator', "
                 "operator_user_id=(SELECT id FROM admin_users WHERE username='approval-script-owner'), "
                 "allowed_actions=ARRAY['nftables.block_incident_source'];")
        result = self.configure(mode="multi_person")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.sql("SELECT mode FROM approval_profile;"), "multi_person")

    def test_invalid_mode_returns_failure_without_caller_flags(self):
        result = self.configure(mode="invalid", operator="approval-script-owner",
                                actions="nftables.block_incident_source", note="test")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.sql("SELECT mode FROM approval_profile;"), "multi_person")

    def test_unknown_operator_returns_failure_without_caller_flags(self):
        result = self.configure(mode="single_operator", operator="missing-operator",
                                actions="nftables.block_incident_source", note="test")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.sql("SELECT mode FROM approval_profile;"), "multi_person")

    def test_missing_mode_is_refused(self):
        self.assertNotEqual(self.configure().returncode, 0)
        self.assertEqual(self.sql("SELECT mode FROM approval_profile;"), "multi_person")


if __name__ == "__main__":
    unittest.main()
