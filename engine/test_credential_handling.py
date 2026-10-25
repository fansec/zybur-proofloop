"""Slice 9 acceptance: no Windows password reaches a process argument list or a generated script.

Green since slice 9 (2026-10-24); it was pending_test_credential_handling.py. The external review
(2026-10-24): smbclient gets `user%password` in argv (visible to every local process), the WMI
helper and the scheduled-task fallback build a shell string with the password, three executors
write host, user and password into Python source that runs through `sudo ip netns exec` (a quote
in a legitimate password breaks it), and the RDP executor puts `/p:<password>` in a bash script.

Spec:
  executors._net.smb_client / smb_client_from: smbclient reads the credentials from an
    authentication file (`-A <path>`, mode 0600, `username = ` / `password = ` / `domain = `
    lines) created for the call and removed after it, in both the plain and the netns path.
  dedup.DedupAllocator.run_in_netns(source_ip, code, timeout=60, stdin_json=None): when given,
    the dict goes to the child's stdin as JSON (`input=`), never into the wrapper file; the wrapper
    sets OPENSSL_CONF from opensslconf.ensure_openssl_conf(), not the old /tmp literal.
  executors psremoting, remote_service, remote_schtask: the generated code reads
    `json.load(sys.stdin)` for host, user and password and interpolates none of them.
  executors._net.wmiexec and remote_schtask._wmiexec_fallback: no shell string carries the
    password; either the in-process DCOM path (executors/wmiexec.py) or a netns snippet fed on
    stdin.
  executors.rdp_keystroke: the password reaches xfreerdp through `/from-stdin`, fed from the
    RDP_PASS environment variable of the script's process, and never appears in the script text.

The fakes below model only what the executors read today; if an executor needs one more field on
the fake ctx or use-case, add it. The assertions are the contract and do not move.
"""
import json
import os
import pathlib
import stat
import subprocess
import unittest
from unittest import mock

SENTINEL = "Pa$$w0rd'\"x"
CFG = {"win_host": "203.0.113.10", "win_user": "Administrator", "win_pass": SENTINEL,
       "dc_domain": "lab.example"}
USECASE = {"id": "t/cred", "title": "t", "rules": ["r"], "technique": "T1059", "tactic": "execution",
           "executor": "x", "params": {}, "safety": "safe"}


class _Run:
    """Records subprocess.run calls and snapshots any `-A` auth file while it still exists."""
    def __init__(self):
        self.calls = []

    def __call__(self, argv, **kw):
        snapshot = {}
        for i, a in enumerate(argv):
            if a == "-A" and i + 1 < len(argv):
                p = argv[i + 1]
                snapshot = {"path": p, "mode": stat.S_IMODE(os.stat(p).st_mode),
                            "text": pathlib.Path(p).read_text()}
        self.calls.append({"argv": list(argv), "kw": kw, "authfile": snapshot})
        return subprocess.CompletedProcess(argv, 0, stdout="SUCCESS", stderr="")


def no_secret_in(argv):
    return all(SENTINEL not in str(a) for a in argv)


class SmbClient(unittest.TestCase):
    def test_smbclient_reads_the_password_from_a_private_auth_file(self):
        from executors import _net
        run = _Run()
        with mock.patch.object(_net.subprocess, "run", run):
            _net.smb_client(CFG, "ls")
        c = run.calls[0]
        self.assertTrue(no_secret_in(c["argv"]), c["argv"])
        self.assertIn("-A", c["argv"])
        self.assertEqual(c["authfile"]["mode"], 0o600)
        self.assertIn(f"password = {SENTINEL}", c["authfile"]["text"])
        self.assertIn("username = Administrator", c["authfile"]["text"])
        self.assertFalse(os.path.exists(c["authfile"]["path"]), "the auth file outlives the call")

    def test_the_netns_path_does_the_same(self):
        from executors import _net
        run = _Run()
        with mock.patch.object(_net.subprocess, "run", run), \
             mock.patch.object(_net, "_ensure_netns", lambda ip: "dedup_test"):
            _net.smb_client_from(CFG, "ls", source_ip="203.0.113.99")
        c = run.calls[0]
        self.assertTrue(no_secret_in(c["argv"]), c["argv"])
        self.assertIn("-A", c["argv"])
        self.assertEqual(c["authfile"]["mode"], 0o600)
        self.assertFalse(os.path.exists(c["authfile"]["path"]))


class RunInNetns(unittest.TestCase):
    def test_stdin_json_goes_to_the_child_and_never_into_the_wrapper_file(self):
        import dedup
        seen = {}

        def fake_run(argv, **kw):
            seen["argv"] = list(argv)
            seen["kw"] = kw
            seen["wrapper"] = pathlib.Path(argv[-1]).read_text()
            return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

        alloc = dedup.DedupAllocator.__new__(dedup.DedupAllocator)
        with mock.patch.object(dedup, "_ensure_netns", lambda ip: "dedup_test"), \
             mock.patch.object(dedup.subprocess, "run", fake_run):
            alloc.run_in_netns("203.0.113.99", "print('hi')", timeout=5, stdin_json={"win_pass": SENTINEL})
        self.assertNotIn(SENTINEL, seen["wrapper"])
        self.assertEqual(json.loads(seen["kw"]["input"])["win_pass"], SENTINEL)
        self.assertTrue(no_secret_in(seen["argv"]))
        self.assertNotIn("/tmp/openssl_legacy.cnf", seen["wrapper"])


class NetnsSnippets(unittest.TestCase):
    """The three executors that run generated Python inside a namespace hand the credentials over on stdin."""

    def _run(self, name):
        import importlib
        mod = importlib.import_module(f"executors.{name}")
        calls = []

        class Dedup:
            def allocate(self, key):
                return "203.0.113.99"

            def run_in_netns(self, source_ip, code, timeout=60, stdin_json=None):
                calls.append({"code": code, "stdin_json": stdin_json})
                return 0, "SUCCESS", ""

        class Ctx:
            cfg = CFG
            dedup = Dedup()
            winrm_factory = None
            firewall = None

        try:
            getattr(mod, name)(dict(USECASE, executor=name), Ctx())
        except Exception:
            pass  # the result shape is not under test here; the recorded call is
        self.assertTrue(calls, f"{name} never reached run_in_netns with this fake ctx")
        return calls[0]

    def test_psremoting_remote_service_and_remote_schtask_take_credentials_on_stdin(self):
        for name in ("psremoting", "remote_service", "remote_schtask"):
            with self.subTest(executor=name):
                c = self._run(name)
                self.assertNotIn(SENTINEL, c["code"])
                self.assertNotIn(CFG["win_host"], c["code"], "the host travels on stdin too")
                self.assertEqual(c["stdin_json"]["win_pass"], SENTINEL)
                self.assertIn("json.load(sys.stdin)", c["code"])


class WmiAndRdp(unittest.TestCase):
    def test_the_wmi_helper_never_puts_the_password_in_a_shell_string(self):
        from executors import _net
        run = _Run()
        with mock.patch.object(_net.subprocess, "run", run):
            try:
                _net.wmiexec(CFG, "whoami")
            except Exception:
                pass
        for c in run.calls:
            self.assertTrue(no_secret_in(c["argv"]), c["argv"])
        self.assertTrue(not run.calls or all(SENTINEL in str(c["kw"].get("input", "")) for c in run.calls),
                        "a subprocess path must feed the password on stdin; in-process is also fine")

    def test_the_scheduled_task_fallback_does_not_build_a_shell_string_with_the_password(self):
        from executors import remote_schtask
        calls = []

        def fake_run(argv, **kw):
            calls.append((list(argv), kw))
            return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

        with mock.patch.object(remote_schtask, "_ensure_netns", lambda ip: "dedup_test"), \
             mock.patch.object(remote_schtask.subprocess, "run", fake_run):
            try:
                remote_schtask._wmiexec_fallback(dict(USECASE, executor="remote_schtask"), CFG,
                                                 "203.0.113.99", None, "2026-10-24T00:00:00Z")
            except Exception:
                pass
        for argv, kw in calls:
            self.assertTrue(no_secret_in(argv), argv)
        src = pathlib.Path(remote_schtask.__file__).read_text()
        self.assertNotIn('{cfg["win_pass"]}@', src, "the user:password@host shell string is gone")

    def test_rdp_feeds_the_password_from_the_environment_not_the_script(self):
        from executors import rdp_keystroke
        src = pathlib.Path(rdp_keystroke.__file__).read_text()
        self.assertNotIn("'/p:' + cfg['win_pass']", src)
        self.assertIn("/from-stdin", src)
        self.assertIn("RDP_PASS", src)


if __name__ == "__main__":
    unittest.main()
