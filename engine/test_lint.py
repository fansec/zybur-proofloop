# rules/engine/test_lint.py
import os, unittest
from lint import lint

HERE = os.path.dirname(__file__)
UC = os.path.join(HERE, "fixtures", "usecases")
EXPORT = os.path.join(HERE, "fixtures", "rules_export.sample.ndjson")
LOCK = os.path.join(HERE, "fixtures", "ruleid.lock.json")

class TestLint(unittest.TestCase):
    def test_clean_registry_has_no_errors(self):
        errs = lint(UC, EXPORT, LOCK)
        self.assertEqual([e for e in errs if "unknown executor" in e], [])
    def test_unknown_executor_flagged(self):
        errs = lint(os.path.join(HERE, "fixtures", "usecases_bad"), EXPORT, LOCK)
        self.assertTrue(any("unknown executor" in e for e in errs))
    def test_safe_pool_is_non_empty_on_the_clean_fixture(self):
        errs = lint(UC, EXPORT, LOCK)
        self.assertEqual([e for e in errs if "safe pool" in e], [])
    def test_safe_without_cleanup_flagged(self):
        errs = lint(os.path.join(HERE, "fixtures", "usecases_bad"), EXPORT, LOCK)
        self.assertTrue(any("requires a non-empty cleanup" in e for e in errs))
    def test_a_winrm_payload_over_the_cmd_exe_limit_is_an_error(self):
        """2026-10-14: the BITS payload encoded to 9,027 characters, cmd.exe refused
        it, and the night read it as executed while nothing ran."""
        errs = lint(os.path.join(HERE, "fixtures", "usecases_bad"), EXPORT, LOCK)
        self.assertTrue(any("winrm-too-long" in e and "over 8000: it would never run" in e for e in errs), errs)
        self.assertEqual([e for e in lint(UC, EXPORT, LOCK) if "it would never run" in e], [])
    def test_destroys_evidence_cannot_be_safe(self):
        errs = lint(os.path.join(HERE, "fixtures", "usecases_bad"), EXPORT, LOCK)
        self.assertTrue(any("destroys_evidence must not be safety:safe" in e for e in errs))

    def test_a_dangling_name_in_a_non_detected_usecase_is_a_fatal_error(self):
        """Until 2026-09-02 renaming a non-detected use-case's rule to something
        that exists nowhere passed this gate in silence."""
        errs = lint(os.path.join(HERE, "fixtures", "usecases_unresolvable"), EXPORT, LOCK)
        fatal = [e for e in errs if not e.startswith("WARN ")]
        self.assertTrue(any("This Rule Does Not Exist Anywhere" in e for e in fatal))

    def test_a_not_enabled_usecase_is_not_a_lint_error(self):
        """`not_enabled` names a rule that is installed and switched OFF, so its
        absence from the enabled export is the declared state, not a defect."""
        errs = lint(UC, EXPORT, LOCK)
        self.assertEqual([e for e in errs if "not in enabled export" in e], [])

    # P-D1: evidence (real_behaviour|stand_in) is required for every safe-pool
    # member (selector.safe_pool's exact 4-filter predicate), WARN elsewhere.
    def test_pool_member_without_evidence_is_fatal(self):
        errs = lint(os.path.join(HERE, "fixtures", "usecases_bad"), EXPORT, LOCK)
        fatal = [e for e in errs if not e.startswith("WARN ")]
        self.assertTrue(any("pool-member-no-evidence" in e and "evidence" in e for e in fatal), fatal)
    def test_non_pool_member_without_evidence_is_a_warning_only(self):
        errs = lint(os.path.join(HERE, "fixtures", "usecases_bad"), EXPORT, LOCK)
        warn = [e for e in errs if e.startswith("WARN ")]
        self.assertTrue(any("non-pool-no-evidence" in e and "evidence" in e for e in warn), warn)
        fatal = [e for e in errs if not e.startswith("WARN ")]
        self.assertFalse(any("non-pool-no-evidence" in e for e in fatal), fatal)
    def test_clean_registry_has_no_evidence_errors_or_warnings(self):
        """Every fixture in the clean registry already carries a valid evidence:
        line, pool member or not."""
        errs = lint(UC, EXPORT, LOCK)
        self.assertEqual([e for e in errs if "evidence" in e], [])


class TestNoArtifactClaimIsChecked(unittest.TestCase):
    """leaves_no_artifact is the second way to be `safe`, so it must not be a
    self-certifying field: the payload is read, and a persisting verb in it makes
    the declaration an error rather than a promise."""

    def _doc(self, command, **kw):
        d = {"id": "x/y", "params": {"command": command}}
        d.update(kw)
        return d

    def test_a_registry_write_contradicts_the_claim(self):
        from lint import _persisting_verbs
        self.assertEqual(
            _persisting_verbs(self._doc('Set-ItemProperty -Path "HK:\\a" -Name "b" -Value 1')),
            ["Set-ItemProperty"])

    def test_a_scheduled_task_contradicts_the_claim(self):
        from lint import _persisting_verbs
        self.assertIn("schtasks /create",
                      _persisting_verbs(self._doc('schtasks /create /tn T /tr cmd.exe')))

    def test_fetching_without_writing_to_disk_does_not(self):
        """The public-ip use-case reads a response body and writes nothing. A bare
        Invoke-WebRequest in the deny list would have failed it."""
        from lint import _persisting_verbs
        self.assertEqual(
            _persisting_verbs(self._doc(
                '$ip = (Invoke-WebRequest -Uri "https://api.ipify.org" -UseBasicParsing).Content')),
            [])

    def test_fetching_to_disk_does(self):
        from lint import _persisting_verbs
        self.assertIn("-OutFile",
                      _persisting_verbs(self._doc('Invoke-WebRequest -Uri $u -OutFile $p')))

    def test_a_named_pipe_redirect_is_not_a_file_write(self):
        """\\\\.\\pipe\\ lives as long as the process does. A generic `>` check would
        have failed the named-pipe impersonation use-case, which is exactly the
        false positive that keeps a real payload out of the rotation."""
        from lint import _persisting_verbs
        self.assertEqual(
            _persisting_verbs(self._doc(r'cmd.exe /c echo T > \\.\pipe\p2a_privesc_test')), [])

class TestLintNoResolve(unittest.TestCase):
    """--no-resolve: the public export lints its use-cases against three made-up rules."""

    def _lock(self, d, doc):
        import json
        p = os.path.join(d, "lock.json")
        with open(p, "w") as f:
            json.dump(doc, f)
        return p

    def test_unresolvable_names_are_not_errors_without_resolution(self):
        errs = lint(os.path.join(HERE, "fixtures", "usecases_unresolvable"), EXPORT, LOCK, resolve=False)
        self.assertFalse(any("not in enabled export" in e for e in errs), errs)
        # ...and still are with it: the flag is the only thing that changes the answer.
        errs = lint(os.path.join(HERE, "fixtures", "usecases_unresolvable"), EXPORT, LOCK)
        self.assertTrue(any("This Rule Does Not Exist Anywhere" in e for e in errs), errs)

    def test_the_rest_of_the_lint_still_runs(self):
        errs = lint(os.path.join(HERE, "fixtures", "usecases_bad"), EXPORT, LOCK, resolve=False)
        self.assertTrue(any("unknown executor" in e for e in errs), errs)
        self.assertTrue(any("requires a non-empty cleanup" in e for e in errs), errs)

    def test_the_lock_is_judged_by_shape_and_by_the_names_the_usecases_carry(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            # The clean fixture's committed lock passes.
            self.assertEqual([e for e in lint(UC, EXPORT, LOCK, resolve=False) if "lock" in e], [])
            # A name the use-cases carry and the lock lacks, and an extra one, are both stale.
            stale = self._lock(d, {"Some Other Rule": {"rule_id": "x", "rule_uuid": None}})
            errs = [e for e in lint(UC, EXPORT, stale, resolve=False) if "stale lock" in e]
            self.assertTrue(any("Sample Rule Two" in e and "missing" in e for e in errs), errs)
            self.assertTrue(any("Some Other Rule" in e and "named by no" in e for e in errs), errs)
            # A malformed entry is named.
            bad = self._lock(d, {"Sample Rule Two": {"rule_id": ""}})
            errs = lint(UC, EXPORT, bad, resolve=False)
            self.assertTrue(any("is not {rule_id: str, rule_uuid: str|null}" in e for e in errs), errs)

    def test_the_summary_line_says_shape_only(self):
        import contextlib, io
        from lint import main
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            main(["--usecases", UC, "--export", EXPORT, "--lock", LOCK, "--no-resolve"])
        self.assertRegex(out.getvalue().splitlines()[-1], r"^lint: \d+ error\(s\), \d+ warning\(s\), shape only \(--no-resolve\)$")


if __name__ == "__main__":
    unittest.main()
