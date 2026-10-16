import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

HOOK = pathlib.Path(__file__).with_name("ready-session.py")


@unittest.skipUnless(sys.platform != "win32", "POSIX process groups")
class HookTests(unittest.TestCase):
    def run_hook(self, body, event=None, timeout="2"):
        with tempfile.TemporaryDirectory() as directory:
            fake = pathlib.Path(directory) / "opv"
            fake.write_text("#!/usr/bin/env python3\n" + body)
            fake.chmod(0o755)
            payload = event if event is not None else {
                "hook_event_name": "SessionStart", "cwd": directory}
            return subprocess.run([sys.executable, str(HOOK), "--env", "dev",
                                   "--opv", str(fake), "--timeout", timeout],
                                  input=json.dumps(payload), text=True,
                                  capture_output=True, timeout=8)

    def receipt(self, findings):
        return "import json\nprint(json.dumps(" + repr({
            "schema_version": 2, "matrix": [{"environment": "dev"}],
            "findings": findings}) + "))\n"

    def test_ready_receipt_produces_session_context(self):
        out = self.run_hook(self.receipt([]))
        self.assertIn("no blocking findings", json.loads(out.stdout)["hookSpecificOutput"]["additionalContext"])

    def test_blocking_findings_are_reported_despite_success_exit(self):
        out = self.run_hook(self.receipt([{"blocking": True}]))
        self.assertIn("1 blocking finding", out.stdout)

    def test_nonblocking_findings_do_not_mark_environment_blocked(self):
        self.assertIn("no blocking findings", self.run_hook(self.receipt([{"blocking": False}])).stdout)

    def test_untrusted_receipt_strings_never_enter_context(self):
        self.assertNotIn("SECRET_MARKER", self.run_hook(self.receipt([
            {"blocking": True, "message": "SECRET_MARKER", "prerequisite": "SECRET_MARKER"}])).stdout)

    def test_failure_stderr_is_not_forwarded(self):
        self.assertNotIn("SECRET_MARKER", self.run_hook(
            "import sys\nprint('SECRET_MARKER', file=sys.stderr)\nsys.exit(1)\n").stdout)

    def test_timeout_returns_unconfirmed_context(self):
        self.assertIn("could not be confirmed", self.run_hook("import time\ntime.sleep(5)\n", timeout="0.2").stdout)

    def test_malformed_receipt_returns_unconfirmed_context(self):
        self.assertIn("could not be confirmed", self.run_hook("print('not JSON')\n").stdout)

    def test_oversized_receipt_returns_unconfirmed_context(self):
        self.assertIn("could not be confirmed", self.run_hook("print('x' * 100000)\n").stdout)

    def test_other_events_do_not_execute_opv(self):
        self.assertEqual("", self.run_hook("raise RuntimeError('must not execute')\n",
                                          {"hook_event_name": "PreToolUse"}).stdout)

    def test_only_readiness_command_is_invoked(self):
        self.assertIn("no blocking findings", self.run_hook(
            "import sys\nassert sys.argv[1:] == ['ready', 'dev', '--json']\n" + self.receipt([])).stdout)

    def test_unknown_schema_returns_unconfirmed_context(self):
        self.assertIn("could not be confirmed", self.run_hook(
            self.receipt([]).replace("'schema_version': 2", "'schema_version': 3")).stdout)

    def test_receipt_from_opv_0_9_is_still_read(self):
        self.assertIn("no blocking findings", self.run_hook(
            self.receipt([]).replace("'schema_version': 2", "'schema_version': 1")).stdout)

    def test_receipt_for_wrong_environment_is_not_reported_ready(self):
        self.assertIn("could not be confirmed", self.run_hook(
            self.receipt([]).replace("'environment': 'dev'", "'environment': 'prod'")).stdout)

    def test_missing_blocking_flag_is_not_reported_ready(self):
        self.assertIn("could not be confirmed", self.run_hook(self.receipt([{}])).stdout)

    def test_failed_command_does_not_report_valid_receipt_as_ready(self):
        self.assertIn("could not be confirmed", self.run_hook(
            self.receipt([]) + "import sys\nsys.exit(1)\n").stdout)

    def test_invalid_cwd_does_not_execute_opv(self):
        self.assertIn("could not be confirmed", self.run_hook(
            "raise RuntimeError('must not execute')\n",
            {"hook_event_name": "SessionStart", "cwd": "relative"}).stdout)


if __name__ == "__main__":
    unittest.main()
