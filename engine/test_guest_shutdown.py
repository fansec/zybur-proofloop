import unittest

import testenv
from run import request_guest_shutdown


def setUpModule():
    testenv.use_fixture_lab_hosts_for_module()


class Response:
    def __init__(self, status=0, stderr=b""):
        self.status_code = status
        self.std_err = stderr
        self.std_out = b""


class Session:
    def __init__(self, response):
        self.response = response
        self.calls = []

    def run_cmd(self, command, args):
        self.calls.append((command, args))
        return self.response


class GuestShutdownTest(unittest.TestCase):
    CFG = {
        "win_host": "192.0.2.87", "win_user": "Administrator", "win_pass": "work-pass",
        "dc_host": "192.0.2.40", "dc_user": "Administrator", "dc_pass": "dc-pass",
        "dc_domain": "LAB", "dc_fqdn": "DC1.lab.invalid",
    }

    def test_domain_controller_uses_clean_windows_shutdown(self):
        session = Session(Response())
        result = request_guest_shutdown(
            "domain_controller", cfg=self.CFG, session_factory=lambda: session)
        self.assertTrue(result["ok"])
        self.assertEqual(result["host"], "dc1")
        self.assertEqual(session.calls, [("shutdown.exe", ["/s", "/t", "0"])])

    def test_failure_redacts_the_target_password(self):
        def failed():
            raise RuntimeError("authentication rejected dc-pass")

        result = request_guest_shutdown(
            "domain_controller", cfg=self.CFG, session_factory=failed)
        self.assertFalse(result["ok"])
        self.assertNotIn("dc-pass", result["error"])
        self.assertIn("[REDACTED]", result["error"])


if __name__ == "__main__":
    unittest.main()
