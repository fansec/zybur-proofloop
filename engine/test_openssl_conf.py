"""Slice 9 acceptance: the OpenSSL legacy-provider config lives in a private, verified place.

Green since slice 9 (2026-10-24); it was pending_test_openssl_conf.py. The external review
(2026-10-24): run.py, dedup.run_in_netns and remote_schtask point OPENSSL_CONF at
/tmp/openssl_legacy.cnf, create it with the process umask (0664 on the dev box) and trust it when
it already exists, so any local user who plants that file controls which OpenSSL providers the
harness loads, including inside the root-run namespace snippets.

Spec: engine/opensslconf.py
  DIR_NAME = "zybur-proofloop-<uid>", FILE_NAME = "openssl_legacy.cnf"
  ensure_openssl_conf(base_dir=None) -> str
    base_dir defaults to $XDG_RUNTIME_DIR, else tempfile.gettempdir(). The directory is created
    0700 and the file 0600 with the legacy-provider stanza; both must be owned by the caller's
    uid and not writable by group or other, or OpenSSLConfError names the offending path. A
    second call returns the same path and changes nothing.
  run.py, dedup.py and remote_schtask.py call it; no source names the old /tmp path.
"""
import os
import pathlib
import stat
import tempfile
import unittest


class OpensslConf(unittest.TestCase):
    def test_a_private_directory_and_file_are_created(self):
        import opensslconf
        with tempfile.TemporaryDirectory() as base:
            p = opensslconf.ensure_openssl_conf(base_dir=base)
            self.assertTrue(p.startswith(base))
            self.assertEqual(os.path.basename(p), opensslconf.FILE_NAME)
            self.assertEqual(stat.S_IMODE(os.stat(os.path.dirname(p)).st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(os.stat(p).st_mode), 0o600)
            text = pathlib.Path(p).read_text()
            self.assertIn("legacy = legacy_sect", text)
            self.assertIn("activate = 1", text)
            self.assertEqual(opensslconf.ensure_openssl_conf(base_dir=base), p, "not idempotent")

    def test_a_foreign_or_loose_file_is_refused_not_trusted(self):
        import opensslconf
        with tempfile.TemporaryDirectory() as base:
            d = os.path.join(base, opensslconf.DIR_NAME)
            os.makedirs(d, mode=0o700)
            p = os.path.join(d, opensslconf.FILE_NAME)
            with open(p, "w") as f:
                f.write("openssl_conf = planted\n")
            os.chmod(p, 0o666)
            with self.assertRaises(opensslconf.OpenSSLConfError) as cm:
                opensslconf.ensure_openssl_conf(base_dir=base)
            self.assertIn(p, str(cm.exception))

    def test_the_default_base_is_the_runtime_dir_or_the_temp_dir(self):
        import opensslconf
        p = opensslconf.ensure_openssl_conf()
        base = os.environ.get("XDG_RUNTIME_DIR") or tempfile.gettempdir()
        self.assertTrue(p.startswith(base), p)
        self.assertIn(str(os.getuid()), os.path.dirname(p))

    def test_no_source_names_the_old_world_writable_path(self):
        here = pathlib.Path(__file__).parent
        hits = sorted(str(f.relative_to(here)) for f in here.rglob("*.py")
                      if not f.name.startswith(("test_", "pending_test_"))
                      and "/tmp/openssl_legacy.cnf" in f.read_text(errors="ignore"))
        self.assertEqual(hits, [])


if __name__ == "__main__":
    unittest.main()
