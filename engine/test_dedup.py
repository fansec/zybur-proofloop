# rules/engine/test_dedup.py
import os, json, tempfile, unittest
from unittest import mock

import dedup
from dedup import build_pool, infra_denylist, DedupAllocator, DedupConfigError

# The pool is configuration since 2026-10-22 (DEDUP_SUBNET, DEDUP_GATEWAY,
# DEDUP_DENYLIST). The values below are a documentation range, not a lab.
CONFIGURED = {
    "DEDUP_SUBNET": "10.20.30.0/24",
    "DEDUP_GATEWAY": "10.20.30.1",
    "DEDUP_DENYLIST": "10.20.30.111",
}


def _env(extra=None):
    """An environment where only the dedup names are set, and no creds file is read."""
    tmp = tempfile.mkdtemp()
    empty = os.path.join(tmp, "empty.creds")
    open(empty, "w").close()
    env = {k: v for k, v in os.environ.items() if not k.startswith("DEDUP_")}
    env["ZYBUR_CREDS_FILE"] = empty
    env.update(extra if extra is not None else CONFIGURED)
    return env


class TestDedup(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.dict(os.environ, _env(), clear=True)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_pool_excludes_the_infra_host_ip(self):
        pool = build_pool()
        self.assertNotIn("10.20.30.111", pool)
        self.assertIn("10.20.30.110", pool)
        self.assertEqual(len(pool), 89)
    def test_assert_pool_safe_rejects_infra_target(self):
        alloc = DedupAllocator({"win_host": "10.20.30.111"}, "/tmp/x.json")
        with self.assertRaises(RuntimeError):
            alloc.assert_pool_safe(alloc.cfg)
    def test_allocate_avoids_recent_ip(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump({"10.20.30.110": 9e18}, f)  # far-future = "just used"
            sp = f.name
        alloc = DedupAllocator({"win_host": "10.20.30.56"}, sp)
        ip = alloc.allocate("test-a")
        self.assertNotEqual(ip, "10.20.30.110")
        os.unlink(sp)

    def test_denylist_is_the_configured_one(self):
        self.assertEqual(infra_denylist(), {"10.20.30.111"})
        with mock.patch.dict(os.environ, {"DEDUP_DENYLIST": "10.20.30.111, 10.20.30.120"}):
            self.assertEqual(infra_denylist(), {"10.20.30.111", "10.20.30.120"})
            self.assertNotIn("10.20.30.120", build_pool())

    def test_a_malformed_denylist_is_refused_not_ignored(self):
        # Each of these once parsed to a set member that matches no address, which
        # would let the infra host back into the pool without a word.
        for bad in ("10.20.30.111;10.20.30.112", "10.20.30.111 10.20.30.112",
                    "10.20.30.111/32", "10.20.30.0111", "host-a", ",", " , ,"):
            with mock.patch.dict(os.environ, {"DEDUP_DENYLIST": bad}):
                with self.assertRaises(DedupConfigError, msg=bad) as cm:
                    build_pool()
                self.assertIn("DEDUP_DENYLIST", str(cm.exception))
                self.assertNotIn("10.20.30", str(cm.exception), "a value in the message")

    def test_a_malformed_denylist_stops_the_pre_detonation_check_too(self):
        alloc = DedupAllocator({"win_host": "10.20.30.56"}, "/tmp/x.json")
        with mock.patch.dict(os.environ, {"DEDUP_DENYLIST": "10.20.30.111;10.20.30.112"}):
            with self.assertRaises(DedupConfigError):
                alloc.assert_pool_safe(alloc.cfg)

    def test_denylist_entries_are_compared_as_addresses(self):
        with mock.patch.dict(os.environ, {"DEDUP_DENYLIST": " 10.20.30.111 ,10.20.30.112,"}):
            self.assertEqual(infra_denylist(), {"10.20.30.111", "10.20.30.112"})


class TestDedupUnconfigured(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.dict(os.environ, _env({}), clear=True)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_pool_names_the_three_env_names_and_no_value(self):
        with self.assertRaises(DedupConfigError) as cm:
            build_pool()
        for name in ("DEDUP_SUBNET", "DEDUP_GATEWAY", "DEDUP_DENYLIST"):
            self.assertIn(name, str(cm.exception))

    def test_allocate_refuses_rather_than_guessing_a_pool(self):
        alloc = DedupAllocator({"win_host": "10.20.30.56"}, "/tmp/x.json")
        with self.assertRaises(DedupConfigError):
            alloc.allocate("test-a")

    def test_a_run_of_executors_that_never_draw_from_the_pool_still_starts(self):
        # run.py checks the pool before every detonation; the WinRM executors need
        # no source address, so an unconfigured pool must not stop them.
        DedupAllocator({"win_host": "10.20.30.56"}, "/tmp/x.json").assert_pool_safe(
            {"win_host": "10.20.30.56"})

    def test_a_partial_configuration_names_only_what_is_missing(self):
        with mock.patch.dict(os.environ, {"DEDUP_SUBNET": "10.20.30.0/24"}):
            with self.assertRaises(DedupConfigError) as cm:
                build_pool()
        self.assertNotIn("DEDUP_SUBNET", str(cm.exception))
        self.assertIn("DEDUP_GATEWAY", str(cm.exception))
        self.assertIn("DEDUP_DENYLIST", str(cm.exception))

    def test_only_a_slash_24_is_a_pool(self):
        with mock.patch.dict(os.environ, dict(CONFIGURED, DEDUP_SUBNET="10.20.0.0/16")):
            with self.assertRaises(DedupConfigError):
                build_pool()

if __name__ == "__main__":
    unittest.main()
