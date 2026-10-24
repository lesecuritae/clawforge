#!/usr/bin/env python3
"""Static check: every operator-facing safety setting the executor reads is passed through by compose.yml,
and the live authorization is NOT (a compose deployment cannot open the live gate by an .env edit).

A setting that is read by the binary but missing from the container environment is silently ignored: an
operator who sets CLAWFORGE_FIREWALL_MAX_TTL_SECONDS in .env would believe the ceiling is enforced."""
import pathlib
import re
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
REQUIRED = [
    "CLAWFORGE_EXECUTOR_DRY_RUN",
    "CLAWFORGE_FIREWALL_NEVER_BLOCK_CIDRS",
    "CLAWFORGE_FIREWALL_MAX_TTL_SECONDS",
    "CLAWFORGE_FIREWALL_MAX_APPLIES_PER_WINDOW",
    "CLAWFORGE_FIREWALL_RATE_WINDOW_SECONDS",
    "CLAWFORGE_FIREWALL_MAX_CONCURRENT_APPLIES_PER_ADAPTER",
]
MUST_NOT_PASS = ["CLAWFORGE_EXECUTOR_LIVE_AUTHORIZATION"]


def executor_environment(compose_text):
    """Names under `clawforge-executor: ... environment:` (top-level service block only)."""
    block = re.search(r"^  clawforge-executor:\n(.*?)(?=^  \S|\Z)", compose_text, re.S | re.M)
    if not block:
        raise AssertionError("clawforge-executor service not found")
    env = re.search(r"^    environment:\n((?:      .*\n|\n)+)", block.group(1), re.M)
    if not env:
        raise AssertionError("executor environment block not found")
    return set(re.findall(r"^      ([A-Z][A-Z0-9_]+):", env.group(1), re.M))


class ComposeExecutorEnv(unittest.TestCase):
    def test_required_settings_are_passed_through(self):
        names = executor_environment((ROOT / "compose.yml").read_text())
        self.assertEqual([n for n in REQUIRED if n not in names], [])

    def test_live_authorization_is_not_wired_into_compose(self):
        names = executor_environment((ROOT / "compose.yml").read_text())
        self.assertEqual([n for n in MUST_NOT_PASS if n in names], [])

    def test_every_required_setting_is_read_by_the_executor(self):
        source = (ROOT / "executor/src/main.rs").read_text() + (ROOT / "firewall-agent/src/lib.rs").read_text()
        for name in REQUIRED:
            self.assertIn(f'"{name}"', source, name)

    def test_control_the_check_detects_a_missing_setting(self):
        old = "  clawforge-executor:\n    environment:\n      CLAWFORGE_EXECUTOR_DRY_RUN: x\n      CLAWFORGE_FIREWALL_NEVER_BLOCK_CIDRS: y\n\n  other:\n    environment:\n      CLAWFORGE_FIREWALL_MAX_TTL_SECONDS: z\n"
        names = executor_environment(old)
        self.assertNotIn("CLAWFORGE_FIREWALL_MAX_TTL_SECONDS", names)  # belongs to another service
        self.assertTrue([n for n in REQUIRED if n not in names])

    def test_env_example_lists_every_required_setting(self):
        text = (ROOT / ".env.example").read_text()
        self.assertEqual([n for n in REQUIRED if not re.search(rf"^{n}=", text, re.M)], [])


if __name__ == "__main__":
    unittest.main()
