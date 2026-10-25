# rules/engine/test_rdp_keystroke.py
"""The Win+R delivery path. Three nights of fake-CAPTCHA ABORTs (2026-07-29,
2026-08-16, 2026-09-04) came from a use-case payload written for a shell executor
being interpolated raw into the generated bash: the first embedded newline ended the
bash string and the rest of the PowerShell was parsed as bash. The verdict said
nothing, because nothing carried the reason out of /tmp.

These tests pin the three properties that make that class of failure impossible:
the keystroke is checked against what a Run dialog can accept, everything reaching
the generated script is shell-quoted, and the password never leaves in the output.
"""
import io
import shlex
import unittest
from unittest import mock

from ctx import Ctx
from result import Result
import executors.plugins  # noqa: F401  (registers rdp_keystroke)
import executors.registry as reg
from executors.rdp_keystroke import (
    _keystroke_problem, _redact, _runmru_values, _keystroke_landed,
    RUN_DIALOG_MAX, PRESEED_VALUES,
)

PASSWORD = "s3cr3t'\"pass"


class FakeSession:
    def run_ps(self, cmd): return None


def make_ctx():
    return Ctx(cfg={"win_host": "192.0.2.65", "win_user": "u", "win_pass": PASSWORD,
                    "attacker_ip": "198.51.100.103"},
               winrm_factory=lambda: FakeSession(), dedup=None, firewall=None)


class ReadbackSession:
    """A WinRM stub that answers the RunMRU readback with a chosen set of value
    strings and returns None for the enable/pre-seed/teardown calls, like the real
    session does. Records every command so a test can assert on what ran."""

    def __init__(self, runmru_values):
        self._values = list(runmru_values)
        self.calls = []

    def run_ps(self, cmd):
        self.calls.append(cmd)
        if "GetValueNames" in cmd:
            body = "\n".join("RUNMRU_VALUE::" + v for v in self._values)
            return mock.Mock(std_out=body.encode("utf-8"), std_err=b"", status_code=0)
        return None


def run_executor(command, session, log_text=""):
    """Drive the executor end to end with a chosen session and a chosen simulator
    log, mocking away the real Xvfb/xfreerdp subprocess, the temp file and the sleeps.
    subprocess.run returns rc 0 so the tool-presence check and the bash run both pass."""

    class Tmp:
        name = "/tmp/does-not-exist_rdp_keystroke.sh"
        def write(self, s): pass
        def close(self): pass

    def fake_open(path, *a, **k):
        if path == "/tmp/rdp_keystroke_sim.log":
            return io.StringIO(log_text)
        raise FileNotFoundError(path)

    ctx = Ctx(cfg={"win_host": "192.0.2.65", "win_user": "Administrator",
                   "win_pass": PASSWORD, "attacker_ip": "198.51.100.103"},
              winrm_factory=lambda: session, dedup=None, firewall=None)
    with mock.patch("time.sleep", lambda *a, **k: None), \
         mock.patch("tempfile.NamedTemporaryFile", lambda **k: Tmp()), \
         mock.patch("subprocess.run", lambda *a, **k: mock.Mock(returncode=0)), \
         mock.patch("os.unlink", lambda p: None), \
         mock.patch("builtins.open", fake_open):
        return reg.get("rdp_keystroke")(uc(command), ctx)


def uc(command):
    return {"id": "t/rdp", "rule_ids": [], "executor": "rdp_keystroke",
            "params": {"shell": "psh", "command": command}}


class TestKeystrokeContract(unittest.TestCase):
    def test_multiline_is_rejected_by_name(self):
        problem = _keystroke_problem('$x = 1\nWrite-Host "two"')
        self.assertIsNotNone(problem)
        self.assertIn("multi-line", problem)

    def test_carriage_return_counts_as_multiline(self):
        self.assertIsNotNone(_keystroke_problem("a\r\nb"))

    def test_over_the_run_dialog_cap_is_rejected(self):
        self.assertIsNotNone(_keystroke_problem("a" * (RUN_DIALOG_MAX + 1)))

    def test_empty_is_rejected(self):
        self.assertIsNotNone(_keystroke_problem("   "))

    def test_a_real_single_line_command_passes(self):
        good = ('powershell.exe -NoProfile -Command '
                '"Write-Output \'Verification ID: CAPTCHA-TEST-12345\'; Start-Sleep 8"')
        self.assertIsNone(_keystroke_problem(good))


class TestBadKeystrokeAborts(unittest.TestCase):
    """A payload a Run dialog cannot take must fail BEFORE the box is touched, and
    the reason must be on the Result, not in a log file."""

    def test_multiline_payload_aborts_with_a_reason_and_touches_nothing(self):
        calls = []
        with mock.patch("subprocess.run", side_effect=AssertionError("no subprocess")), \
             mock.patch.object(FakeSession, "run_ps", lambda self, c: calls.append(c)):
            r = reg.get("rdp_keystroke")(uc("line one\nline two"), make_ctx())
        self.assertIsInstance(r, Result)
        self.assertFalse(r.executed)
        self.assertTrue(r.status.startswith("BAD_KEYSTROKE:"), r.status)
        self.assertIn("multi-line", r.status)
        self.assertEqual(calls, [], "RDP was reconfigured on the box for a payload that could never run")


class TestGeneratedScriptIsQuoted(unittest.TestCase):
    """Whatever the use-case says, the generated bash must stay one script."""

    def _script_for(self, command):
        seen = {}

        class Tmp:
            name = "/tmp/does-not-exist_rdp_keystroke.sh"
            def write(self, s): seen["script"] = s
            def close(self): pass

        with mock.patch("time.sleep", lambda *a, **k: None), \
             mock.patch("tempfile.NamedTemporaryFile", lambda **k: Tmp()), \
             mock.patch("subprocess.run", lambda *a, **k: mock.Mock(returncode=0)), \
             mock.patch("os.unlink", lambda p: None):
            reg.get("rdp_keystroke")(uc(command), make_ctx())
        return seen["script"]

    def test_quotes_in_the_keystroke_do_not_escape_the_bash_string(self):
        command = 'powershell.exe -Command "Write-Output \'Verification ID: X\'"'
        script = self._script_for(command)
        line = next(l for l in script.splitlines() if "xdotool type" in l)
        self.assertIn(shlex.quote(command), line)
        # The real check: bash itself agrees the script is parseable.
        self.assertEqual(0, __import__("subprocess").run(
            ["bash", "-n", "/dev/stdin"], input=script, text=True).returncode)

    def test_the_password_is_fed_from_the_environment_not_quoted_into_the_script(self):
        # Replaces test_the_password_is_quoted_into_the_xfreerdp_line (2026-10-24): that test pinned
        # the password inside the script as `/p:<password>`, which `ps` showed to every local user.
        # The password now rides in RDP_PASS and reaches xfreerdp3 on stdin; a password full of
        # quotes can no longer break the script because it is never in it.
        script = self._script_for("cmd.exe")
        self.assertNotIn(PASSWORD, script)
        self.assertNotIn("/p:", script)
        self.assertIn('printf \'%s\\n\' "$RDP_PASS" | xfreerdp3', script)
        self.assertIn("/from-stdin", script)
        self.assertEqual(0, __import__("subprocess").run(
            ["bash", "-n", "/dev/stdin"], input=script, text=True).returncode)

    def test_the_password_reaches_the_script_process_through_its_environment(self):
        seen = {}

        def fake_run(argv, **kw):
            if argv[:1] == ["bash"]:
                seen["env"] = kw.get("env") or {}
                seen["argv"] = list(argv)
            return mock.Mock(returncode=0)

        class Tmp:
            name = "/tmp/does-not-exist_rdp_keystroke.sh"
            def write(self, s): pass
            def close(self): pass

        with mock.patch("time.sleep", lambda *a, **k: None), \
             mock.patch("tempfile.NamedTemporaryFile", lambda **k: Tmp()), \
             mock.patch("subprocess.run", fake_run), \
             mock.patch("os.unlink", lambda p: None):
            reg.get("rdp_keystroke")(uc("cmd.exe"), make_ctx())
        self.assertEqual(seen["env"].get("RDP_PASS"), PASSWORD)
        self.assertNotIn(PASSWORD, " ".join(seen["argv"]))


class TestRedaction(unittest.TestCase):
    def test_the_password_never_rides_out_on_the_log_tail(self):
        log = f"bash: syntax error near xfreerdp3 /p:{PASSWORD} /cert:ignore"
        out = _redact(log, {"win_pass": PASSWORD})
        self.assertNotIn(PASSWORD, out)
        self.assertIn("***", out)

    def test_no_password_configured_is_not_an_error(self):
        self.assertEqual(_redact("plain", {}), "plain")


class TestRunMRUReadbackHelpers(unittest.TestCase):
    """The parse-and-match logic that turns a RunMRU readback into landed/not-landed."""

    def test_readback_parses_marker_lines_and_drops_the_rest(self):
        session = ReadbackSession(["cmd.exe /c whoami.exe\\1", "notepad.exe\\1"])
        self.assertEqual(_runmru_values(session),
                         ["cmd.exe /c whoami.exe\\1", "notepad.exe\\1"])

    def test_readback_returns_none_when_the_session_raises(self):
        class Boom:
            def run_ps(self, cmd): raise RuntimeError("winrm down")
        self.assertIsNone(_runmru_values(Boom()))

    def test_preseed_alone_does_not_count_as_landed(self):
        self.assertFalse(_keystroke_landed(list(PRESEED_VALUES), "notepad.exe"))

    def test_the_keystroke_value_counts_as_landed(self):
        self.assertTrue(_keystroke_landed(
            list(PRESEED_VALUES) + ["cmd.exe /c whoami.exe\\1"], "cmd.exe /c whoami.exe"))


class TestKeystrokeMustLandToSucceed(unittest.TestCase):
    """The vacuous-success defect: a clean-looking log is not a detonation. Only a
    fresh RunMRU value written by explorer.exe proves the keystroke reached a desktop."""

    KEYSTROKE = "cmd.exe /c whoami.exe"

    def test_empty_runmru_is_a_named_failure_not_success(self):
        r = run_executor(self.KEYSTROKE, ReadbackSession([]))
        self.assertIsInstance(r, Result)
        self.assertFalse(r.executed)
        self.assertTrue(r.status.startswith("KEYSTROKE_NOT_LANDED:"), r.status)
        self.assertIn("no desktop", r.status)

    def test_only_preseed_values_is_a_named_failure(self):
        r = run_executor(self.KEYSTROKE, ReadbackSession(list(PRESEED_VALUES)))
        self.assertFalse(r.executed)
        self.assertTrue(r.status.startswith("KEYSTROKE_NOT_LANDED:"), r.status)
        self.assertIn("no desktop", r.status)

    def test_complete_in_the_log_alone_does_not_win(self):
        # The exact shape of the six-night false pass: the bash log says COMPLETE, but
        # nothing new is in RunMRU, so the verdict must be a named failure, not SUCCESS.
        r = run_executor(self.KEYSTROKE, ReadbackSession(list(PRESEED_VALUES)),
                         log_text="Win+R...\nTyping keystroke...\nEnter...\nCOMPLETE\n")
        self.assertFalse(r.executed)
        self.assertNotEqual(r.status, "SUCCESS")
        self.assertTrue(r.status.startswith("KEYSTROKE_NOT_LANDED:"), r.status)

    def test_a_fresh_non_matching_value_reads_as_typed_but_not_recorded(self):
        r = run_executor(self.KEYSTROKE,
                         ReadbackSession(list(PRESEED_VALUES) + ["explorer.exe\\1"]))
        self.assertFalse(r.executed)
        self.assertIn("typed but not recorded", r.status)

    def test_the_keystroke_value_is_a_success(self):
        r = run_executor(self.KEYSTROKE,
                         ReadbackSession(list(PRESEED_VALUES) + [self.KEYSTROKE + "\\1"]))
        self.assertTrue(r.executed)
        self.assertEqual(r.status, "SUCCESS")

    def test_a_fake_captcha_keystroke_with_no_shell_prefix_still_lands(self):
        # The second use-case types a "Verification ID" powershell line, not cmd.exe;
        # the readback must match on the actual keystroke, not on a shell prefix.
        captcha = ('powershell.exe -NoProfile -Command '
                   '"Write-Output \'Verification ID: CAPTCHA-TEST-12345\'; Start-Sleep 8"')
        r = run_executor(captcha, ReadbackSession(list(PRESEED_VALUES) + [captcha + "\\1"]))
        self.assertTrue(r.executed)
        self.assertEqual(r.status, "SUCCESS")

    def test_a_local_xdotool_failure_is_named_in_the_reason(self):
        r = run_executor(self.KEYSTROKE, ReadbackSession(list(PRESEED_VALUES)),
                         log_text="Win+R...\nXDOTOOL_FAIL: type\n")
        self.assertFalse(r.executed)
        self.assertTrue(r.status.startswith("KEYSTROKE_NOT_LANDED:"), r.status)
        self.assertIn("xdotool", r.status)

    def test_the_password_never_appears_on_the_not_landed_path(self):
        # The simulator log carries the password (bash echoes a failing line verbatim);
        # a not-landed verdict must not carry it out on the status or the output.
        leaky_log = f"bash: xfreerdp3 /p:{PASSWORD} failed\nCOMPLETE\n"
        r = run_executor(self.KEYSTROKE, ReadbackSession([]), log_text=leaky_log)
        self.assertFalse(r.executed)
        self.assertNotIn(PASSWORD, r.status)
        self.assertNotIn(PASSWORD, r.output)


if __name__ == "__main__":
    unittest.main()
