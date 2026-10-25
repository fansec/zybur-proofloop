# rules/engine/test_executors_direct_wiring.py
"""Wiring tests for the ported DIRECT_* plugins: each is registered and returns a
Result with a hermetic fake ctx (no real network / netns / subprocess I/O). Behavioral
correctness is the live golden step (Task 17), not this offline test."""
import unittest
from unittest import mock
from ctx import Ctx
from result import Result
import executors.plugins  # noqa: F401  (registers all plugins)
import executors.registry as reg

DIRECT_PLUGINS = [
    "smb_write", "smb_exe_transfer", "smb_ransom_note", "smb_rename",
    "remote_service", "remote_schtask", "psremoting", "rdp_keystroke",
    "hidden_user", "rare_smb", "dcomexec", "wmiexec",
]


class FakeWinRMResult:
    def __init__(self, code=0, out=b"Created 7 files ok"):
        self.status_code = code
        self.std_out = out
        self.std_err = b""


class FakeSession:
    def run_ps(self, cmd): return FakeWinRMResult()
    def run_cmd(self, shell, args): return FakeWinRMResult()


class FakeDedup:
    def __init__(self):
        self.allocated = []
    def allocate(self, key):
        self.allocated.append(key)
        return "198.51.100.150"
    def run_in_netns(self, source_ip, code, timeout=60, stdin_json=None):
        return (0, "SUCCESS", "")


class FakeProc:
    def __init__(self, returncode=1, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def _fake_run(*a, **k):
    return FakeProc()


def make_ctx(dedup=None):
    return Ctx(
        cfg={"win_host": "10.255.255.1", "win_user": "u", "win_pass": "p",
             "attacker_ip": "198.51.100.103"},
        winrm_factory=lambda: FakeSession(),
        dedup=dedup or FakeDedup(),
        firewall=None,
    )


class TestDirectWiring(unittest.TestCase):
    def setUp(self):
        self._patchers = [
            mock.patch("time.sleep", lambda *a, **k: None),
            mock.patch("subprocess.run", _fake_run),
        ]
        for p in self._patchers:
            p.start()

    def tearDown(self):
        for p in self._patchers:
            p.stop()

    def test_all_registered_and_return_result(self):
        for name in DIRECT_PLUGINS:
            with self.subTest(plugin=name):
                self.assertIn(name, reg.executor_names())
                uc = {"id": f"t/{name}", "rule_ids": [], "executor": name,
                      "params": {"shell": "psh", "command": "cmd.exe"}}
                r = reg.get(name)(uc, make_ctx())
                self.assertIsInstance(r, Result)

    def test_dedup_keyed_by_usecase_id(self):
        d = FakeDedup()
        uc = {"id": "impact/smb_rename", "rule_ids": [], "executor": "smb_rename",
              "params": {"shell": "psh", "command": ""}}
        reg.get("smb_rename")(uc, make_ctx(dedup=d))
        self.assertIn("impact/smb_rename", d.allocated)


if __name__ == "__main__":
    unittest.main()
