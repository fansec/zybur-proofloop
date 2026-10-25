"""Edges of the slice 9 credential handling that test_credential_handling.py and test_openssl_conf.py
leave open (2026-10-24): what the smbclient authentication file does and does not hold, what
opensslconf refuses, and what the namespace wrapper contains.
"""
import json
import os
import stat
import subprocess
import tempfile
import unittest
from unittest import mock

import dedup
import opensslconf
from executors import _net

PASS = "Pa$$w0rd'\"x"
CFG = {"win_host": "203.0.113.10", "win_user": "Administrator", "win_pass": PASS, "dc_domain": "lab.example"}


class AuthFile(unittest.TestCase):
    def read_during(self, cfg):
        with _net._auth_file(cfg) as path:
            with open(path) as f:
                return path, f.read(), stat.S_IMODE(os.stat(path).st_mode)

    def test_it_holds_username_and_password_and_no_domain_line(self):
        # A domain line would change the NTLM domain the workstation sees: with only these two,
        # smbclient applies its own default workgroup, exactly as `-U user%password` did.
        path, text, mode = self.read_during(CFG)
        self.assertEqual(text, f"username = Administrator\npassword = {PASS}\n")
        self.assertNotIn("domain", text)
        self.assertNotIn("lab.example", text)
        self.assertEqual(mode, 0o600)
        self.assertFalse(os.path.exists(path))

    def test_a_domain_user_is_passed_through_for_smbclient_to_split(self):
        _, text, _ = self.read_during(dict(CFG, win_user="LAB\\Administrator"))
        self.assertIn("username = LAB\\Administrator\n", text)

    def test_the_file_is_removed_when_the_call_raises(self):
        seen = {}
        with self.assertRaises(subprocess.TimeoutExpired):
            with _net._auth_file(CFG) as path:
                seen["path"] = path
                raise subprocess.TimeoutExpired("smbclient", 30)
        self.assertFalse(os.path.exists(seen["path"]))

    def test_a_line_break_is_refused_by_field_name_and_nothing_is_written(self):
        before = set(os.listdir(tempfile.gettempdir()))
        for field, cfg in (("win_pass", dict(CFG, win_pass="a\nusername = root")), ("win_user", dict(CFG, win_user="a\r"))):
            with self.assertRaises(ValueError) as cm:
                with _net._auth_file(cfg):
                    self.fail("the file must not be made")
            self.assertIn(field, str(cm.exception))
            self.assertNotIn("root", str(cm.exception))
        self.assertEqual(set(os.listdir(tempfile.gettempdir())) - before, set())


class OpensslConf(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.base = self._tmp.name
        self.dir = os.path.join(self.base, opensslconf.DIR_NAME)
        self.addCleanup(self._tmp.cleanup)

    def test_a_second_call_writes_nothing(self):
        p = opensslconf.ensure_openssl_conf(base_dir=self.base)
        before = os.stat(p).st_mtime_ns
        self.assertEqual(opensslconf.ensure_openssl_conf(base_dir=self.base), p)
        self.assertEqual(os.stat(p).st_mtime_ns, before)

    def test_a_deleted_file_is_made_again(self):
        p = opensslconf.ensure_openssl_conf(base_dir=self.base)
        os.unlink(p)
        self.assertEqual(opensslconf.ensure_openssl_conf(base_dir=self.base), p)
        with open(p) as f:
            self.assertEqual(f.read(), opensslconf.CONF)

    def test_a_symlinked_directory_is_refused_before_anything_is_changed(self):
        target = os.path.join(self.base, "elsewhere")
        os.mkdir(target, 0o755)
        os.symlink(target, self.dir)
        with self.assertRaises(opensslconf.OpenSSLConfError) as cm:
            opensslconf.ensure_openssl_conf(base_dir=self.base)
        self.assertIn(self.dir, str(cm.exception))
        self.assertEqual(stat.S_IMODE(os.stat(target).st_mode), 0o755, "the link's target must not be chmod-ed")

    def test_a_symlinked_file_is_refused(self):
        p = opensslconf.ensure_openssl_conf(base_dir=self.base)
        os.unlink(p)
        decoy = os.path.join(self.base, "decoy.cnf")
        with open(decoy, "w") as f:
            f.write("openssl_conf = planted\n")
        os.symlink(decoy, p)
        with self.assertRaises(opensslconf.OpenSSLConfError) as cm:
            opensslconf.ensure_openssl_conf(base_dir=self.base)
        self.assertIn(p, str(cm.exception))
        self.assertIn("symlink", str(cm.exception))

    def test_a_loose_directory_that_is_ours_is_tightened_not_refused(self):
        os.mkdir(self.dir, 0o755)
        p = opensslconf.ensure_openssl_conf(base_dir=self.base)
        self.assertEqual(stat.S_IMODE(os.stat(self.dir).st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(os.stat(p).st_mode), 0o600)

    def test_a_group_writable_directory_is_a_refusal(self):
        os.mkdir(self.dir, 0o700)
        os.chmod(self.dir, 0o770)
        with self.assertRaises(opensslconf.OpenSSLConfError) as cm:
            opensslconf.ensure_openssl_conf(base_dir=self.base)
        self.assertIn("writable by group or other", str(cm.exception))

    def test_a_base_that_does_not_exist_is_a_named_error(self):
        gone = os.path.join(self.base, "no", "such", "place")
        with self.assertRaises(opensslconf.OpenSSLConfError) as cm:
            opensslconf.ensure_openssl_conf(base_dir=gone)
        self.assertIn(gone, str(cm.exception))


class NamespaceWrapper(unittest.TestCase):
    def run_it(self, **kw):
        seen = {}

        def fake_run(argv, **k):
            seen["argv"], seen["kw"] = list(argv), k
            with open(argv[-1]) as f:
                seen["wrapper"] = f.read()
            return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

        alloc = dedup.DedupAllocator.__new__(dedup.DedupAllocator)
        with mock.patch.object(dedup, "_ensure_netns", lambda ip: "dedup_test"), \
             mock.patch.object(dedup.subprocess, "run", fake_run):
            alloc.run_in_netns("203.0.113.99", "print('hi')", timeout=5, **kw)
        return seen

    def test_the_wrapper_puts_the_engine_first_and_points_openssl_at_the_verified_file(self):
        seen = self.run_it()
        self.assertIn(f"sys.path.insert(0, {dedup.ENGINE_DIR!r})", seen["wrapper"])
        self.assertIn(f"os.environ[\"OPENSSL_CONF\"] = {opensslconf.ensure_openssl_conf()!r}", seen["wrapper"])
        self.assertIn("print('hi')", seen["wrapper"])

    def test_without_stdin_json_the_child_inherits_stdin_as_before(self):
        self.assertNotIn("input", self.run_it()["kw"])

    def test_with_stdin_json_the_dict_is_the_childs_stdin(self):
        seen = self.run_it(stdin_json={"win_pass": PASS, "n": 1})
        self.assertEqual(json.loads(seen["kw"]["input"]), {"win_pass": PASS, "n": 1})


if __name__ == "__main__":
    unittest.main()
