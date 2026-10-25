# rules/engine/test_executors_generic.py
import re
import unittest
from ctx import Ctx
from result import Result
import executors.caldera_command as cc
import executors.winrm_command as wc
import executors.registry as reg

class FakeCaldera:
    def create_ability(self, uc): return "abil-1"
    def run_ability(self, aid, uc, session):
        from result import make_result, Verdict
        return make_result(uc, "SUCCESS", True, op_id="op-1")

class FakeWinRMResult:
    def __init__(self, code): self.status_code = code
    std_out = b"OK"; std_err = b""

class FakeSession:
    def run_ps(self, cmd): return FakeWinRMResult(0)
    def run_cmd(self, shell, args): return FakeWinRMResult(0)

class TestGenericExecutors(unittest.TestCase):
    def test_caldera_command_registered_and_runs(self):
        uc = {"id": "c/x", "rule_ids": ["r1"], "executor": "caldera_command",
              "params": {"shell": "psh", "command": "whoami"}}
        ctx = Ctx(cfg={}, caldera=FakeCaldera())
        r = reg.get("caldera_command")(uc, ctx)
        self.assertIsInstance(r, Result)
        self.assertTrue(r.executed)
    def test_winrm_command_stamps_and_executes(self):
        uc = {"id": "c/y", "rule_ids": [], "executor": "winrm_command",
              "params": {"shell": "psh", "command": "whoami"}}
        ctx = Ctx(cfg={}, winrm_factory=lambda: FakeSession())
        r = reg.get("winrm_command")(uc, ctx)
        self.assertTrue(r.executed)
        self.assertIsNotNone(r.attack_start)
        self.assertIsNotNone(r.attack_end)


class TestWinrmCommandLength(unittest.TestCase):
    """2026-10-14: cmd.exe refuses a command string over 8191 characters and the
    WinRM call still returns, so the BITS payload (9,027) read as executed while
    PowerShell never started. Refused before anything is sent."""
    def _sess(self):
        class Sess:
            def __init__(self): self.calls = []
            def run_ps(self, c): self.calls.append(c); return FakeWinRMResult(0)
            def run_cmd(self, shell, args): self.calls.append(args); return FakeWinRMResult(0)
        return Sess()

    def test_an_over_long_psh_payload_is_refused_unsent(self):
        sess = self._sess()
        uc = {"id": "x/long", "params": {"shell": "psh", "command": "Write-Host " + "x" * 3100},
              "cleanup": "Remove-Item z"}
        r = wc.winrm_command(uc, Ctx(cfg={}, winrm_factory=lambda: sess))
        self.assertFalse(r.executed)
        self.assertIn("it would never run", r.status)
        self.assertEqual(sess.calls, [], "nothing may be sent, not even the cleanup")

    def test_an_over_long_cmd_payload_is_refused_too(self):
        sess = self._sess()
        uc = {"id": "x/long", "params": {"shell": "cmd", "command": "echo " + "x" * 8100}}
        r = wc.winrm_command(uc, Ctx(cfg={}, winrm_factory=lambda: sess))
        self.assertFalse(r.executed)
        self.assertEqual(sess.calls, [])

    def test_a_payload_at_the_size_that_ran_live_still_runs(self):
        from cmdline import run_ps_cmdline_len, MAX_RUN_PS_CMDLINE
        cmd = "Write-Host " + "x" * 2900
        self.assertLessEqual(run_ps_cmdline_len(cmd), MAX_RUN_PS_CMDLINE)
        sess = self._sess()
        r = wc.winrm_command({"id": "x/ok", "params": {"shell": "psh", "command": cmd}},
                             Ctx(cfg={}, winrm_factory=lambda: sess))
        self.assertTrue(r.executed)
        self.assertEqual(sess.calls, [cmd])


class TestWinrmSilentFailure(unittest.TestCase):
    """2026-10-14: a payload Microsoft Defender Antivirus blocked before PowerShell
    started came back exit 1 with empty stdout as a bare EXECUTED, saying nothing."""
    def _run(self, code, out, err=b""):
        class R:
            status_code = code; std_out = out; std_err = err
        class Sess:
            def run_ps(self, c): return R()
            def run_cmd(self, shell, args): return R()
        uc = {"id": "x/silent", "params": {"shell": "psh", "command": "Write-Output hi"}}
        return wc.winrm_command(uc, Ctx(cfg={}, winrm_factory=lambda: Sess()))

    def test_non_zero_exit_with_no_output_says_so_and_is_left_to_the_verifier(self):
        # Still executed: the startup-shortcut case was stopped after its attack step
        # and DETECTED, so refusing to grade it would have hidden a real detection.
        r = self._run(1, b"", b"Access is denied.\r\n")
        self.assertTrue(r.executed)
        self.assertEqual(r.status, "EXECUTED: exit 1 with no output (Access is denied.)")

    def test_non_zero_exit_with_output_is_still_executed(self):
        r = self._run(1, b"ZYB_X_FAILED something")
        self.assertTrue(r.executed)
        self.assertEqual(r.status, "EXECUTED")

    def test_success_with_no_output_is_still_executed(self):
        self.assertTrue(self._run(0, b"").executed)


class TestWinrmCleanup(unittest.TestCase):
    def _ctx_and_session(self):
        class R:
            std_out = b"ok"; status_code = 0
        class Sess:
            def __init__(self): self.ps = []; self.cmd = []
            def run_ps(self, c): self.ps.append(c); return R()
            def run_cmd(self, shell, args): self.cmd.append(args); return R()
        sess = Sess()
        from ctx import Ctx
        ctx = Ctx(cfg={}, winrm_factory=lambda: sess)
        return ctx, sess

    def test_psh_cleanup_runs_via_run_ps(self):
        from executors.winrm_command import winrm_command
        ctx, sess = self._ctx_and_session()
        uc = {"id": "x/y", "params": {"shell": "psh", "command": "whoami"},
              "cleanup": "Remove-Item z -Force"}
        winrm_command(uc, ctx)
        self.assertIn("Remove-Item z -Force", sess.ps)

    def test_cmd_cleanup_runs_via_run_cmd(self):
        from executors.winrm_command import winrm_command
        ctx, sess = self._ctx_and_session()
        uc = {"id": "x/y", "params": {"shell": "cmd", "command": "echo hi"},
              "cleanup": 'schtasks /delete /tn "T" /f'}
        winrm_command(uc, ctx)
        self.assertTrue(any('schtasks /delete /tn "T" /f' in a for a in sess.cmd))

    def test_no_cleanup_key_is_a_noop(self):
        from executors.winrm_command import winrm_command
        ctx, sess = self._ctx_and_session()
        winrm_command({"id": "x/y", "params": {"shell": "psh", "command": "whoami"}}, ctx)
        self.assertEqual(sess.ps, ["whoami"])  # attack only, no cleanup call


class TestWinrmCommandCanaryNonce(unittest.TestCase):
    """C-S5, 2026-10-19: the canary's old command (`echo zybur-proofloop-canary-%RANDOM%`) relied
    on a cmd.exe RUNTIME expansion. WinRS wraps every run_cmd in its own outer `cmd.exe /C`
    (rules/engine/cmdline.py's own measured docstring), so the OUTER cmd.exe process WinRS
    creates is created with the literal text it was handed - %RANDOM% unexpanded - while the
    INNER cmd.exe that outer process spawns parses and expands %RANDOM% for real. Two
    process-creation events, two different values, and the rule's own
    process.args:zybur-proofloop-canary-* query matched both: two alerts, and the outer one's
    nonce ("%RANDOM%", literally) was never written anywhere - a receipt for it would be
    the "nonce never written" redline plan section 9 calls out.

    These tests prove the fix at the level this suite can actually reach without a live
    Windows box: the literal text winrm_command hands to WinRM, and what the SAME
    nonce-extraction regex reads off both a simulated outer-wrap and inner command line.
    """
    NONCE_RE = re.compile(r'zybur-proofloop-canary-(\S+)')

    def _sess(self):
        class R:
            status_code = 0
            std_out = b"zybur-proofloop-canary-ignored-stdout"
            std_err = b""
        class Sess:
            def __init__(self): self.calls = []
            def run_cmd(self, shell, args):
                self.calls.append(args)
                return R()
        return Sess()

    def _run(self):
        sess = self._sess()
        uc = {"id": "canary/zybur-proofloop-canary-endpoint", "params": {
            "shell": "cmd", "command": "echo zybur-proofloop-canary-{{NONCE}}"}}
        r = wc.winrm_command(uc, Ctx(cfg={}, winrm_factory=lambda: sess))
        return r, sess.calls[0][1]  # the Result, and the literal command sent to WinRM

    def test_no_percent_random_left_in_the_command_sent_to_winrm(self):
        _, command = self._run()
        self.assertNotIn("%RANDOM%", command)
        self.assertNotIn("{{NONCE}}", command, "the placeholder must be substituted, not left literal")

    def test_result_nonce_is_the_exact_literal_templated_into_the_command(self):
        r, command = self._run()
        m = self.NONCE_RE.search(command)
        self.assertIsNotNone(m, command)
        self.assertEqual(r.nonce, m.group(1))
        self.assertRegex(r.nonce, r'^[0-9a-f]{8}$', "secrets.token_hex(4), the project's own per-run-token convention")

    def test_a_usecase_with_no_NONCE_placeholder_gets_no_nonce(self):
        # Every other winrm_command use-case must see no behaviour change: nonce stays None
        # and nothing is substituted that was not already there.
        sess = self._sess()
        uc = {"id": "x/y", "params": {"shell": "cmd", "command": "whoami"}}
        r = wc.winrm_command(uc, Ctx(cfg={}, winrm_factory=lambda: sess))
        self.assertIsNone(r.nonce)
        self.assertEqual(sess.calls[0][1], "whoami")

    def test_outer_and_inner_winrs_command_lines_now_carry_the_identical_nonce(self):
        """Models the specific failure the assessment found. WinRS performs no shell
        expansion of its own (cmdline.py): the outer `cmd.exe /C` process it creates is
        created with the command text verbatim, and the inner cmd.exe that outer process
        spawns re-parses that SAME text. Simulate both command lines an EDR would record for
        one detonation, today (fixed) and under the old %RANDOM% command, and compare what
        the SAME nonce-extraction regex reads off each.
        """
        _, command = self._run()  # e.g. "echo zybur-proofloop-canary-a1b2c3d4"

        # TODAY (fixed): WinRS hands the outer cmd.exe this literal text verbatim - this is
        # that outer process's own recorded command line.
        outer_cmdline = f"cmd.exe /C cmd /c {command}"
        # The inner cmd.exe the outer one spawns re-parses the identical text; with no
        # %RANDOM% left anywhere, re-parsing it changes nothing.
        inner_cmdline = command
        outer_nonce = self.NONCE_RE.search(outer_cmdline).group(1)
        inner_nonce = self.NONCE_RE.search(inner_cmdline).group(1)
        self.assertEqual(outer_nonce, inner_nonce,
                         "nothing is left for either process-creation event to expand differently")

        # THE OLD BUG, reconstructed, to prove this is a real fix and not a coincidence of
        # the test: %RANDOM% is unexpanded on the outer process's own command line (WinRS
        # does no shell expansion) and only the inner shell's own parse of it expands it.
        old_command = "echo zybur-proofloop-canary-%RANDOM%"
        old_outer_cmdline = f"cmd.exe /C cmd /c {old_command}"
        old_outer_capture = self.NONCE_RE.search(old_outer_cmdline).group(1)
        # Stands in for whatever cmd.exe's own %RANDOM% actually produced at runtime inside
        # the inner shell - this suite cannot run real cmd.exe, but any concrete value proves
        # the point: it is never the literal string "%RANDOM%".
        simulated_runtime_expansion = "30142"
        old_inner_cmdline = f"echo zybur-proofloop-canary-{simulated_runtime_expansion}"
        old_inner_capture = self.NONCE_RE.search(old_inner_cmdline).group(1)
        self.assertEqual(old_outer_capture, "%RANDOM%",
                         "the outer alert's own nonce, unexpanded - never written anywhere on purpose")
        self.assertNotEqual(old_outer_capture, old_inner_capture,
                            "the bug this fix removes: two process-creation events disagreeing on the nonce")


if __name__ == "__main__":
    unittest.main()
