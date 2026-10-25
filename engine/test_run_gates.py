# rules/engine/test_run_gates.py
"""The gates that stop a run before it measures nothing (slice 1, 2026-10-22).

A new detonation without a verifier writes INCONCLUSIVE rows for every use-case, and a
--preflight that says `ok` for a pool the engine later refuses sends the founder into
a night that dies after the lab is powered on. Both are refusals that nothing else
would catch, so each one is held here.
"""
import contextlib
import io
import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import dedup
import run as runmod
import testenv

HERE = os.path.dirname(os.path.abspath(__file__))
GOOD_POOL = {"DEDUP_SUBNET": "10.20.30.0/24", "DEDUP_GATEWAY": "10.20.30.1",
             "DEDUP_DENYLIST": "10.20.30.111"}
UC = {"id": "x/y", "executor": "winrm_command", "target": "workstation", "technique": "T0000"}


class Stop(Exception):
    """Raised by the stubbed DedupAllocator: the run got past the verifier gate."""


class TestVerifyRefusal(unittest.TestCase):
    def run_main(self, argv, **env):
        tmp = tempfile.mkdtemp()
        env.setdefault("ZYBUR_ENV_ROOT", tmp)   # no .env.shared here, so no key to find
        env.setdefault("LAB_HOSTS_FILE", testenv.LAB_HOSTS_FIXTURE)
        err = io.StringIO()
        with testenv.no_lab_values(**env), \
                mock.patch.object(runmod, "load_enabled_rules", return_value={}), \
                mock.patch.object(runmod, "load_usecases", return_value=[UC]), \
                mock.patch.object(runmod, "CalderaClient"), \
                mock.patch.object(runmod, "DedupAllocator", side_effect=Stop) as alloc, \
                contextlib.redirect_stderr(err):
            try:
                rc = runmod.main(argv)
            except Stop:
                rc = "reached the allocator"
        return rc, err.getvalue(), alloc

    def test_verify_without_url_and_key_refuses_before_any_detonation(self):
        rc, err, alloc = self.run_main(["--id", "x/y", "--verify"])
        self.assertEqual(rc, 2)
        self.assertIn("engine: ES_URL or ES_API_KEY not set; refusing to detonate without a verifier", err)
        alloc.assert_not_called()

    def test_verify_with_a_key_but_no_url_refuses(self):
        rc, err, alloc = self.run_main(["--id", "x/y", "--verify"], ES_API_KEY="marker-key")
        self.assertEqual(rc, 2)
        self.assertIn("refusing to detonate without a verifier", err)
        self.assertNotIn("marker-key", err)
        alloc.assert_not_called()

    def test_all_is_a_verifying_run_too(self):
        rc, err, alloc = self.run_main(["--all"])
        self.assertEqual(rc, 2)
        alloc.assert_not_called()

    def test_no_verify_still_proceeds(self):
        # Only the verify path is gated: a run that asks for no verification is the
        # operator's explicit choice and must reach the allocator as before.
        rc, err, alloc = self.run_main(["--id", "x/y", "--no-verify"])
        self.assertEqual(rc, "reached the allocator", err)
        alloc.assert_called_once()

    def test_verify_with_url_and_key_proceeds(self):
        rc, err, alloc = self.run_main(["--id", "x/y", "--verify"],
                                       ES_URL="https://es.example.invalid", ES_API_KEY="k")
        self.assertEqual(rc, "reached the allocator", err)


class TestAssertPoolSafeWarning(unittest.TestCase):
    def test_an_unset_denylist_is_never_silent(self):
        alloc = dedup.DedupAllocator({"win_host": "10.20.30.56"}, "/tmp/x.json")
        with testenv.no_lab_values():
            with self.assertLogs("engine.dedup", level="WARNING") as cm:
                alloc.assert_pool_safe({"win_host": "10.20.30.56"})
        self.assertIn("DEDUP_DENYLIST", "\n".join(cm.output))

    def test_a_set_denylist_does_not_warn(self):
        alloc = dedup.DedupAllocator({"win_host": "10.20.30.56"}, "/tmp/x.json")
        with testenv.no_lab_values(**GOOD_POOL):
            with self.assertNoLogs("engine.dedup", level="WARNING"):
                alloc.assert_pool_safe({"win_host": "10.20.30.56"})


class TestPreflightHoldsTheValuesToTheFormat(unittest.TestCase):
    def preflight(self, executors, **pool):
        tmp = tempfile.mkdtemp()
        env = {k: v for k, v in os.environ.items()
               if not k.startswith(("CALDERA_", "WIN_", "DC_", "ATTACKER_", "ES_", "ELASTIC_",
                                    "PROXMOX_", "DEDUP_", "LAB_HOSTS"))}
        env.update({"ZYBUR_CREDS_FILE": os.devnull, "ZYBUR_ENV_ROOT": tmp,
                    "LAB_HOSTS_FILE": testenv.LAB_HOSTS_FIXTURE,
                    "ES_URL": "https://es.example.invalid", "ES_API_KEY": "k",
                    "ATTACKER_IP": "10.20.30.5", "WIN_USER": "u", "WIN_PASS": "p"})
        env.update(pool)
        p = subprocess.run([sys.executable, os.path.join(HERE, "run.py"), "--preflight",
                            "--executors", executors], env=env, capture_output=True, text=True, cwd=HERE)
        return p

    def test_a_good_pool_passes(self):
        p = self.preflight("wmiexec", **GOOD_POOL)
        self.assertEqual((p.returncode, p.stdout.strip()), (0, "preflight ok"), p.stdout + p.stderr)

    def test_a_semicolon_denylist_is_named_not_passed(self):
        p = self.preflight("wmiexec", **dict(GOOD_POOL, DEDUP_DENYLIST="10.20.30.5;10.20.30.6"))
        self.assertEqual(p.returncode, 1, p.stdout + p.stderr)
        self.assertEqual(p.stdout.strip(), "preflight: missing DEDUP_DENYLIST")
        self.assertNotIn("10.20.30", p.stdout, "a value in the output")

    def test_a_slash_16_subnet_is_named_not_passed(self):
        p = self.preflight("wmiexec", **dict(GOOD_POOL, DEDUP_SUBNET="10.20.0.0/16"))
        self.assertEqual(p.returncode, 1, p.stdout + p.stderr)
        self.assertEqual(p.stdout.strip(), "preflight: missing DEDUP_SUBNET")

    def test_a_gateway_that_is_not_an_address_is_named(self):
        p = self.preflight("wmiexec", **dict(GOOD_POOL, DEDUP_GATEWAY="not-an-ip"))
        self.assertEqual(p.stdout.strip(), "preflight: missing DEDUP_GATEWAY")

    def test_executors_that_never_draw_from_the_pool_ignore_a_bad_pool(self):
        p = self.preflight("winrm_command", **dict(GOOD_POOL, DEDUP_DENYLIST="a;b"))
        self.assertEqual((p.returncode, p.stdout.strip()), (0, "preflight ok"), p.stdout + p.stderr)


if __name__ == "__main__":
    unittest.main()
