"""Slice 8 acceptance: the small release-hygiene findings of the 2026-10-24 external review.

Green since slice 8 (2026-10-24); it was pending_test_release_hygiene.py.

  pyasn1==0.6.2 carries 8 OSV advisories (checked 2026-10-24); 0.6.4 carries none.
  GOLDEN.md still says "Five-state model" and "54 tests".
  CI runs Python 3.12 only while pyproject claims >=3.11, and audits no dependency.
  `pip install .` fails: "Multiple top-level packages discovered in a flat-layout".
  docs/run.md asks for passwordless sudo on `ip`, which is root for anyone who can run it.
  README.md implies a nightly scheduler the public tree does not include.

The public files live in scripts/oss-export/files in the private checkout and at the export's root
in the public tree; the tests that need them look in both places and skip when neither exists.
"""
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve().parent
KIT = HERE.parent.parent / "scripts" / "oss-export" / "files"
EXPORT_ROOT = HERE.parent


def public(rel):
    for base in (KIT, EXPORT_ROOT):
        p = base / rel
        if p.exists():
            return p
    return None


class Dependencies(unittest.TestCase):
    def test_pyasn1_is_pinned_past_the_advisories(self):
        req = (HERE / "requirements.txt").read_text()
        m = re.search(r"^pyasn1==(\d+)\.(\d+)\.(\d+)$", req, re.M)
        self.assertIsNotNone(m, "pyasn1 is not pinned in requirements.txt")
        self.assertGreaterEqual(tuple(int(x) for x in m.groups()), (0, 6, 4),
                                "pyasn1 below 0.6.4 carries known decoder advisories")
        pp = public("pyproject.toml")
        if pp is not None:
            self.assertIn(f"pyasn1=={m.group(0).split('==')[1]}", pp.read_text(),
                          "pyproject.toml pins a different pyasn1 than requirements.txt")


class Golden(unittest.TestCase):
    def test_golden_describes_the_six_verdicts_and_not_a_stale_suite(self):
        g = (HERE / "GOLDEN.md").read_text()
        self.assertNotIn("Five-state", g)
        self.assertNotIn("54 tests", g)
        for v in ("DETECTED", "PREVENTED", "MISSED", "PENDING", "INCONCLUSIVE", "ABORT"):
            self.assertIn(v, g)
        self.assertIn("six", g.lower())


class PublicFiles(unittest.TestCase):
    def setUp(self):
        if public("pyproject.toml") is None:
            self.skipTest("no public files beside this engine (neither the export kit nor an export root)")

    def test_ci_tests_every_python_the_project_claims_and_audits_dependencies(self):
        ci = public(".github/workflows/ci.yml").read_text()
        self.assertIn('"3.11"', ci)
        self.assertIn('"3.12"', ci)
        self.assertIn("pip-audit", ci)

    def test_pip_install_of_the_public_tree_succeeds(self):
        with tempfile.TemporaryDirectory() as d:
            shutil.copy(public("pyproject.toml"), d)
            os.makedirs(os.path.join(d, "engine"))
            os.makedirs(os.path.join(d, "usecases"))
            pathlib.Path(d, "engine", "run.py").write_text("")
            pathlib.Path(d, "README.md").write_text("x\n")
            r = subprocess.run([sys.executable, "-m", "pip", "install", ".", "--dry-run", "--no-deps",
                                "--no-build-isolation", "--break-system-packages", "-q"],
                               cwd=d, capture_output=True, text=True, timeout=180)
            self.assertEqual(r.returncode, 0, (r.stdout + r.stderr)[-800:])

    def test_run_md_scopes_the_sudo_rule_and_warns(self):
        md = public("docs/run.md").read_text()
        self.assertIn("Cmnd_Alias", md, "a scoped sudoers rule is spelled out")
        self.assertIn("root", md, "the guide says what ip netns exec amounts to")
        self.assertNotIn("passwordless sudo for `ip`", md)

    def test_readme_says_the_scheduler_is_not_included(self):
        md = public("README.md").read_text()
        self.assertTrue(("cron" in md or "systemd" in md) and "not included" in md,
                        "the README implies a nightly scheduler the public tree does not carry")


if __name__ == "__main__":
    unittest.main()
