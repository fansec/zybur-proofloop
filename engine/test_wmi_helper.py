"""run_wmi, and the child process that carries host, user and password on stdin (slice 9, 2026-10-24).

test_credential_handling.py is the contract: no password reaches a process argument list or a generated
script. These pin the new pieces that contract leans on, against the fake impacket test_wmiexec.py
already uses: the DCOM call chain as a function, the stdin payload, the first-command-decides rule of
the child, and the single namespace invocation remote_schtask's fallback now makes.
"""
import io
import socket
import subprocess
import sys
import unittest
from unittest import mock

import executors.plugins  # noqa: F401  (registers the executors)
from executors import _net, remote_schtask
from executors import wmiexec as wmi
from test_wmiexec import fake_impacket

PASS = "Pa$$w0rd'\"x"
CFG = {"win_host": "203.0.113.10", "win_user": "Administrator", "win_pass": PASS}


def run_wmi_with_fake(command="echo hi", **kw):
    log = []
    with mock.patch.dict(sys.modules, fake_impacket(log, **kw)):
        return log, wmi.run_wmi(CFG, command, timeout=5)


class RunWmi(unittest.TestCase):
    def test_a_created_process_is_success_and_names_its_pid(self):
        log, (rc, out) = run_wmi_with_fake()
        self.assertEqual((rc, out), (0, "SUCCESS: Win32_Process.Create ReturnValue=0 ProcessId=4242"))
        create = next(e for e in log if e[0] == "Create")
        self.assertEqual(create[1:3], ("cmd.exe /Q /c echo hi", "C:\\"))
        connect = next(e for e in log if e[0] == "DCOMConnection")
        self.assertEqual(connect[1][:3], ("203.0.113.10", "Administrator", PASS))
        self.assertIn(("disconnect",), log)

    def test_a_nonzero_return_value_is_a_failure_line(self):
        _, (rc, out) = run_wmi_with_fake(return_value=2)
        self.assertEqual(rc, 1)
        self.assertTrue(out.startswith("WMI_FAIL: Win32_Process.Create ReturnValue=2"), out)

    def test_a_connection_error_is_a_failure_line_not_an_exception(self):
        log, (rc, out) = run_wmi_with_fake(fail_at="connect")
        self.assertEqual(rc, 1)
        self.assertIn("Connection refused", out)
        self.assertNotIn(("disconnect",), log, "nothing connected, so nothing to disconnect")

    def test_a_failure_after_connecting_still_disconnects(self):
        log, (rc, out) = run_wmi_with_fake(fail_at="Create")
        self.assertEqual(rc, 1)
        self.assertIn(("disconnect",), log)

    def test_the_socket_default_timeout_is_restored(self):
        before = socket.getdefaulttimeout()
        run_wmi_with_fake()
        self.assertEqual(socket.getdefaulttimeout(), before)


class ChildProtocol(unittest.TestCase):
    def test_a_password_full_of_quotes_travels_as_itself(self):
        payload = wmi.child_payload(CFG, [("echo hi", 0)], timeout=7)
        self.assertIn(f"win_pass={PASS}\n", payload)
        out = io.StringIO()
        log = []
        with mock.patch.dict(sys.modules, fake_impacket(log)):
            rc = wmi.child_main(payload, out)
        self.assertEqual(rc, 0)
        self.assertIn("SUCCESS: Win32_Process.Create", out.getvalue())
        connect = next(e for e in log if e[0] == "DCOMConnection")
        self.assertEqual(connect[1][2], PASS)

    def test_a_line_break_in_a_value_is_refused_by_field_name_only(self):
        for field, cfg in (("win_pass", dict(CFG, win_pass="a\nb")), ("win_user", dict(CFG, win_user="a\rb")),
                           ("win_host", dict(CFG, win_host="h\n"))):
            with self.assertRaises(ValueError) as cm:
                wmi.child_payload(cfg, [("echo", 0)])
            self.assertIn(field, str(cm.exception))
            self.assertNotIn("a\nb", str(cm.exception))

    def test_a_command_with_a_line_break_is_refused_too(self):
        with self.assertRaises(ValueError):
            wmi.child_payload(CFG, [("echo a\necho b", 0)])

    def test_the_first_command_is_the_connection_test(self):
        results = iter([(1, "WMI_FAIL: Could not connect"), (0, "SUCCESS: later")])
        out = io.StringIO()
        with mock.patch.object(wmi, "run_wmi", lambda cfg, command, timeout=30: next(results)), \
             mock.patch("time.sleep") as sleep:
            rc = wmi.child_main(wmi.child_payload(CFG, [("c1", 3), ("c2", 5)]), out)
        self.assertEqual(rc, 1)
        self.assertEqual(out.getvalue().strip().splitlines(), ["WMI_FAIL: Could not connect"])
        sleep.assert_not_called()

    def test_a_later_failure_is_printed_and_does_not_stop_the_rest(self):
        results = iter([(0, "SUCCESS: one"), (1, "WMI_FAIL: two"), (0, "SUCCESS: three")])
        seen = []
        out = io.StringIO()

        def fake(cfg, command, timeout=30):
            seen.append(command)
            return next(results)

        with mock.patch.object(wmi, "run_wmi", fake), mock.patch("time.sleep") as sleep:
            rc = wmi.child_main(wmi.child_payload(CFG, [("c1", 3), ("c2", 5), ("c3", 0)]), out)
        self.assertEqual((rc, seen), (0, ["c1", "c2", "c3"]))
        self.assertEqual(out.getvalue().strip().splitlines(), ["SUCCESS: one", "WMI_FAIL: two", "SUCCESS: three"])
        self.assertEqual([c.args[0] for c in sleep.call_args_list], [3.0, 5.0])

    def test_the_boot_program_compiles_and_holds_paths_but_no_credential(self):
        boot = wmi.child_boot()
        compile(boot, "<child-boot>", "exec")
        self.assertIn("OPENSSL_CONF", boot)
        self.assertIn("child_main", boot)
        self.assertNotIn(PASS, boot)


class NetWmiexec(unittest.TestCase):
    def test_the_helper_runs_a_child_with_the_credentials_on_stdin(self):
        calls = []

        def fake_run(argv, **kw):
            calls.append((list(argv), kw))
            return subprocess.CompletedProcess(argv, 0, stdout="SUCCESS: Win32_Process.Create", stderr="")

        with mock.patch.object(_net.subprocess, "run", fake_run):
            rc, out = _net.wmiexec(CFG, "whoami")
        (argv, kw), = calls
        self.assertEqual(argv[:2], [sys.executable, "-c"])
        self.assertTrue(all(PASS not in str(a) for a in argv))
        self.assertIn(f"win_pass={PASS}\n", kw["input"])
        self.assertIn("command=whoami\n", kw["input"])
        self.assertEqual((rc, out), (0, "SUCCESS: Win32_Process.Create"))


class SchtaskFallback(unittest.TestCase):
    USECASE = {"id": "t/schtask", "title": "t", "rules": ["r"], "technique": "T1053", "tactic": "execution",
               "executor": "remote_schtask", "params": {}, "safety": "safe"}

    def run_fallback(self, returncode=0, stdout="SUCCESS: a\nSUCCESS: b\nSUCCESS: c"):
        calls = []

        def fake_run(argv, **kw):
            calls.append((list(argv), kw))
            return subprocess.CompletedProcess(argv, returncode, stdout=stdout, stderr="")

        with mock.patch.object(remote_schtask, "_ensure_netns", lambda ip: "dedup_test"), \
             mock.patch.object(remote_schtask.subprocess, "run", fake_run), \
             mock.patch("time.sleep") as sleep:
            result = remote_schtask._wmiexec_fallback(self.USECASE, CFG, "203.0.113.99", None, "2026-10-24T00:00:00Z")
        return result, calls, sleep

    def test_one_namespace_invocation_carries_all_three_commands(self):
        result, calls, sleep = self.run_fallback()
        self.assertEqual(len(calls), 1, "one sudo, one child, not one per command")
        argv, kw = calls[0]
        self.assertEqual(argv[:5], ["sudo", "ip", "netns", "exec", "dedup_test"])
        self.assertTrue(all(PASS not in str(a) for a in argv))
        self.assertEqual(kw["input"].count("command=schtasks"), 3)
        self.assertIn("pause=3\n", kw["input"])
        self.assertIn("pause=5\n", kw["input"])
        self.assertEqual(result.status, "SUCCESS")
        sleep.assert_not_called()      # the child sleeps between commands, in the namespace

    def test_a_first_command_that_cannot_connect_is_a_connect_failure(self):
        result, calls, _ = self.run_fallback(returncode=1, stdout="WMI_FAIL: Could not connect")
        self.assertEqual(result.status, "WMI_CONNECT_FAIL")

    def test_a_failure_line_with_exit_zero_still_counts_when_it_is_the_first(self):
        result, _, _ = self.run_fallback(returncode=0, stdout="WMI_FAIL: NT_STATUS_LOGON_FAILURE\nSUCCESS: b")
        self.assertEqual(result.status, "WMI_CONNECT_FAIL")


if __name__ == "__main__":
    unittest.main()
