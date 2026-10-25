import unittest
from datetime import datetime, timezone
from unittest import mock

from cmdline import MAX_RUN_PS_CMDLINE, run_ps_cmdline_len
from ctx import Ctx
from executors.ad_network import (
    AD_ACCOUNT_SETTLE_DELAY_S, ATTACK_MARKER, CLEANUP_ATTEMPTS, CLEANUP_MARKER, CLEANUP_RETRY_DELAY_S,
    PROBE_MARKER, OPERATIONS, NIGHTLY_SAFE_OPERATIONS, _backup_scripts,
    _ephemeral_computer_scripts, _failed_auth_scripts, _failed_burst_scripts,
    ad_network, run_backup_remote_registry, run_ephemeral_computer_ntlm,
    run_failed_logon_burst, run_failed_logons_then_success, run_machine_auth,
)


CFG = {
    "target": "domain_controller", "win_host": "192.0.2.40",
    "win_user": "Administrator", "win_pass": "not-a-real-password",
    "dc_pass": "not-a-real-password", "dc_domain": "LAB",
    "dc_fqdn": "dc1.lab.invalid",
}


class Response:
    def __init__(self, out=b"", err=b"", code=0):
        self.std_out = out
        self.std_err = err
        self.status_code = code


class FakeFactory:
    """A WinRM session factory whose cleanups and probes can be made to fail.

    cleanup_failures / probe_failures: how many of the first calls fail (a large
    number means always). cleanup_raises turns a failed cleanup into a dropped
    transport instead of a missing marker. `runs` records (session number, kind)
    so a test can prove every cleanup and probe got a session of its own.
    """

    def __init__(self, residual=False, setup_code=0, cleanup_failures=0,
                 cleanup_raises=False, probe_failures=0, failure_text="server not operational"):
        self.sessions = 0
        self.scripts = []
        self.runs = []
        self.residual = residual
        self.setup_code = setup_code
        self.cleanup_failures = cleanup_failures
        self.cleanup_raises = cleanup_raises
        self.probe_failures = probe_failures
        self.failure_text = failure_text
        self.cleanup_calls = 0
        self.probe_calls = 0

    def __call__(self):
        self.sessions += 1
        number = self.sessions
        outer = self

        class Session:
            def run_ps(self, script):
                outer.scripts.append(script)
                if "ZYBUR_REMOTE_REGISTRY_BASELINE" in script:
                    outer.runs.append((number, "baseline"))
                    return Response(b"ZYBUR_REMOTE_REGISTRY_BASELINE:Stopped:Manual\n")
                if PROBE_MARKER in script:
                    outer.probe_calls += 1
                    outer.runs.append((number, "probe"))
                    dirty = outer.residual or outer.probe_calls <= outer.probe_failures
                    value = "ZYBUR_AD_NETWORK_RESIDUAL:test" if dirty else PROBE_MARKER
                    return Response((value + "\n").encode())
                if CLEANUP_MARKER in script:
                    outer.cleanup_calls += 1
                    outer.runs.append((number, "cleanup"))
                    if outer.cleanup_calls <= outer.cleanup_failures:
                        if outer.cleanup_raises:
                            raise ConnectionError(outer.failure_text)
                        return Response(b"", outer.failure_text.encode(), 1)
                    return Response((CLEANUP_MARKER + "\n").encode())
                outer.runs.append((number, "attack"))
                return Response((ATTACK_MARKER + "\n").encode(),
                                b"setup failed" if outer.setup_code else b"",
                                outer.setup_code)

        return Session()


class FakeSmb:
    def __init__(self, label):
        self.label = label
        self.trees = []
        self.logged_off = False

    def connectTree(self, share):
        self.trees.append(share)
        return 1

    def logoff(self):
        self.logged_off = True


class TestMachineAuthentication(unittest.TestCase):
    def test_closed_set_contains_all_network_paths(self):
        self.assertEqual(OPERATIONS, {
            "ephemeral_computer_ntlm", "machine_smb_ntlm",
            "machine_ntlm_relay_sequence", "machine_kerberos_relay_sequence",
            "backup_operator_remote_registry",
            "failed_logon_burst",
            "failed_logons_then_success",
        })
        self.assertEqual(NIGHTLY_SAFE_OPERATIONS, {
            "ephemeral_computer_ntlm", "failed_logon_burst",
            "failed_logons_then_success"})

    def test_ntlm_relay_opens_admin_pipe_before_machine_auth(self):
        events = []
        clients = []

        def factory(cfg, user, password="", nthash="", kerberos=False):
            events.append(("auth", user, kerberos, bool(nthash)))
            smb = FakeSmb(user)
            clients.append(smb)
            return smb

        def pipe(smb, name):
            events.append(("pipe", smb.label, name))

        summary = run_machine_auth(
            CFG, "machine_ntlm_relay_sequence",
            hash_reader=lambda *_: "a" * 32, smb_factory=factory,
            pipe_opener=pipe)
        self.assertEqual(events, [
            ("auth", "Administrator", False, False),
            ("pipe", "Administrator", "samr"),
            ("auth", "DC1$", False, True),
        ])
        self.assertNotIn("a" * 32, summary)
        self.assertTrue(all(x.logged_off for x in clients))

    def test_kerberos_machine_auth_is_explicit(self):
        calls = []
        run_machine_auth(
            CFG, "machine_kerberos_relay_sequence",
            hash_reader=lambda *_: "b" * 32,
            smb_factory=lambda cfg, user, password="", nthash="", kerberos=False:
                calls.append((user, kerberos)) or FakeSmb(user),
            pipe_opener=lambda *_: None)
        self.assertEqual(calls[-1], ("DC1$", True))


class TestManagedAccounts(unittest.TestCase):
    def test_ephemeral_computer_uses_three_sessions_and_proves_cleanup(self):
        factory = FakeFactory()
        clients = []
        summary = run_ephemeral_computer_ntlm(
            CFG, factory, token="0123abcd", password="Ephemeral!aA9",
            smb_factory=lambda *_args, **_kwargs: clients.append(FakeSmb("D$")) or clients[-1],
            sleep_fn=lambda _seconds: None)
        self.assertEqual(factory.sessions, 3)
        self.assertIn("cleanup independently proven", summary)
        self.assertTrue(clients[-1].logged_off)
        self.assertTrue(any("SamAccountName 'D$'" in s for s in factory.scripts))

    def test_ephemeral_computer_residual_fails(self):
        factory = FakeFactory(residual=True)
        with self.assertRaisesRegex(RuntimeError, "residual state"):
            run_ephemeral_computer_ntlm(
                CFG, factory, token="0123abcd",
                password="Ephemeral!aA9",
                smb_factory=lambda *_args, **_kwargs: FakeSmb("D$"),
                sleep_fn=lambda _seconds: None)
        self.assertEqual(factory.probe_calls, CLEANUP_ATTEMPTS)

    def test_backup_registry_restores_baseline_in_four_sessions(self):
        factory = FakeFactory()
        opened = []
        summary = run_backup_remote_registry(
            CFG, factory, token="0123abcd", password="Ephemeral!aA9",
            smb_factory=lambda *_args, **_kwargs: FakeSmb("backup"),
            pipe_opener=lambda _smb, pipe: opened.append(pipe))
        self.assertEqual(factory.sessions, 4)
        self.assertEqual(opened, ["winreg"])
        self.assertIn("independently restored", summary)

    def test_five_disposable_failures_are_followed_by_one_success(self):
        outcomes = iter([False, False, False, False, False, True])
        seen = []

        def auth(_cfg, user, password):
            seen.append((user, password))
            return next(outcomes)

        factory = FakeFactory()
        summary = run_failed_logons_then_success(
            CFG, factory, token="0123abcd", password="Ephemeral!aA9",
            auth_fn=auth)
        self.assertEqual(len(seen), 6)
        self.assertEqual(len({user for user, _ in seen[:5]}), 5)
        self.assertNotIn(seen[-1][0], {user for user, _ in seen[:5]})
        self.assertTrue(all(candidate == "Ephemeral!aA9" for _, candidate in seen))
        self.assertTrue(any("$enabled = ($i -eq 5)" in s for s in factory.scripts))
        self.assertIn("cleanup independently proven", summary)
        self.assertEqual(factory.sessions, 3)

    def test_failed_logon_sequence_still_cleans_when_success_leg_fails(self):
        factory = FakeFactory()
        with self.assertRaisesRegex(RuntimeError, "final disposable"):
            run_failed_logons_then_success(
                CFG, factory, token="0123abcd", password="Ephemeral!aA9",
                auth_fn=lambda *_: False)
        self.assertEqual(factory.sessions, 3)

    def test_burst_uses_two_disabled_admin_shaped_accounts_and_110_attempts(self):
        seen = []
        sleeps = []

        def auth(_cfg, user, password):
            seen.append((user, password))
            return False

        factory = FakeFactory()
        summary = run_failed_logon_burst(
            CFG, factory, token="0123abcd", password="Ephemeral!aA9",
            auth_fn=auth, sleep_fn=sleeps.append,
            now_fn=lambda: datetime(2026, 9, 5, 12, 30, 45, tzinfo=timezone.utc))
        self.assertEqual(len(seen), 110)
        self.assertEqual(len({user for user, _ in seen}), 2)
        self.assertTrue(all("admin" in user for user, _ in seen))
        self.assertEqual(sleeps, [17])
        self.assertTrue(all(candidate == "Ephemeral!aA9" for _, candidate in seen))
        self.assertTrue(any("-Enabled $false" in s for s in factory.scripts))
        self.assertIn("cleanup independently proven", summary)
        self.assertEqual(factory.sessions, 3)

    def test_burst_still_cleans_if_a_disabled_credential_is_accepted(self):
        factory = FakeFactory()
        with self.assertRaisesRegex(RuntimeError, "disabled disposable"):
            run_failed_logon_burst(
                CFG, factory, token="0123abcd", password="Ephemeral!aA9",
                auth_fn=lambda *_: True, sleep_fn=lambda _seconds: None,
                now_fn=lambda: datetime(2026, 9, 5, 12, 30, 5, tzinfo=timezone.utc))
        self.assertEqual(factory.sessions, 3)

    def test_executor_redacts_configured_password(self):
        import executors.ad_network as mod
        original = mod.run_operation
        mod.run_operation = lambda *_: (_ for _ in ()).throw(RuntimeError(CFG["win_pass"]))
        try:
            uc = {"id": "credential-access/relay", "rule_ids": ["r1"],
                  "executor": "ad_network", "params": {"operation": "machine_smb_ntlm"}}
            result = ad_network(uc, Ctx(cfg=CFG, winrm_factory=FakeFactory()))
        finally:
            mod.run_operation = original
        self.assertFalse(result.executed)
        self.assertNotIn(CFG["win_pass"], result.status + result.output)


class TestCleanupRetry(unittest.TestCase):
    """Added 2026-10-14 (triage n=35): every cleanup is retried in fresh sessions,
    and a residue that outlives the last attempt is a failure, never a SUCCESS."""

    def _cleanup_sessions_are_fresh(self, factory):
        # Every cleanup and every probe ran in a session nothing else used.
        numbers = [n for n, kind in factory.runs if kind in ("cleanup", "probe")]
        self.assertEqual(len(numbers), len(set(numbers)))
        attack = {n for n, kind in factory.runs if kind in ("attack", "baseline")}
        self.assertFalse(attack & set(numbers))

    def test_first_cleanup_drops_then_a_fresh_session_cleans(self):
        factory = FakeFactory(cleanup_failures=1, cleanup_raises=True)
        sleeps = []
        summary = run_ephemeral_computer_ntlm(
            CFG, factory, token="0123abcd", password="Ephemeral!aA9",
            smb_factory=lambda *_args, **_kwargs: FakeSmb("D$"), sleep_fn=sleeps.append)
        self.assertIn("cleanup independently proven", summary)
        self.assertEqual(factory.cleanup_calls, 2)
        self.assertEqual(factory.probe_calls, 2)
        self.assertEqual(sleeps, [AD_ACCOUNT_SETTLE_DELAY_S, CLEANUP_RETRY_DELAY_S])
        self.assertEqual(factory.sessions, 1 + 2 * 2)
        self._cleanup_sessions_are_fresh(factory)

    def test_backup_cleanup_that_never_succeeds_fails_and_names_the_account(self):
        password = "Ephemeral!aA9"
        factory = FakeFactory(cleanup_failures=99, failure_text="dropped holding " + password)
        sleeps = []
        with self.assertRaisesRegex(RuntimeError, f"after {CLEANUP_ATTEMPTS} attempts") as raised:
            run_backup_remote_registry(
                CFG, factory, token="0123abcd", password=password,
                smb_factory=lambda *_args, **_kwargs: FakeSmb("backup"),
                pipe_opener=lambda *_: None, sleep_fn=sleeps.append)
        message = str(raised.exception)
        self.assertIn("zv-bak-0123abcd", message)
        self.assertIn("Backup Operators", message)
        self.assertNotIn(password, message)
        self.assertIn("[REDACTED]", message)
        self.assertEqual(factory.cleanup_calls, CLEANUP_ATTEMPTS)
        self.assertEqual(factory.probe_calls, CLEANUP_ATTEMPTS)
        self.assertEqual(sleeps, [CLEANUP_RETRY_DELAY_S] * (CLEANUP_ATTEMPTS - 1))
        self._cleanup_sessions_are_fresh(factory)

    def test_a_clean_probe_does_not_excuse_a_failed_cleanup(self):
        # The probe reads clean, but the cleanup never printed its marker, so the
        # script did not run to its end. Same rule as dcsync.py: both must pass.
        factory = FakeFactory(cleanup_failures=99)
        with self.assertRaisesRegex(RuntimeError, "cleanup was not proven after"):
            run_failed_logons_then_success(
                CFG, factory, token="0123abcd", password="Ephemeral!aA9",
                auth_fn=lambda _cfg, user, _pw: user.startswith("zv-f6-"),
                sleep_fn=lambda _seconds: None)

    def test_absence_proof_failure_reruns_cleanup_then_passes(self):
        factory = FakeFactory(probe_failures=1)
        summary = run_failed_logon_burst(
            CFG, factory, token="0123abcd", password="Ephemeral!aA9",
            auth_fn=lambda *_: False, sleep_fn=lambda _seconds: None,
            now_fn=lambda: datetime(2026, 10, 14, 12, 30, 5, tzinfo=timezone.utc))
        self.assertIn("cleanup independently proven", summary)
        self.assertEqual(factory.cleanup_calls, 2)
        self.assertEqual(factory.probe_calls, 2)
        self._cleanup_sessions_are_fresh(factory)

    def test_residue_that_survives_every_attempt_names_the_users(self):
        factory = FakeFactory(residual=True)
        with self.assertRaisesRegex(RuntimeError, "residual state") as raised:
            run_failed_logon_burst(
                CFG, factory, token="0123abcd", password="Ephemeral!aA9",
                auth_fn=lambda *_: False, sleep_fn=lambda _seconds: None,
                now_fn=lambda: datetime(2026, 10, 14, 12, 30, 5, tzinfo=timezone.utc))
        self.assertIn("zv-admin-a-0123abcd", str(raised.exception))
        self.assertEqual(factory.probe_calls, CLEANUP_ATTEMPTS)

    def test_executor_reports_an_unproven_cleanup_as_an_error_not_success(self):
        import executors.ad_network as mod
        factory = FakeFactory(cleanup_failures=99, cleanup_raises=True)
        with mock.patch.object(
                mod, "run_operation",
                lambda cfg, _op, sf: mod.run_ephemeral_computer_ntlm(
                    cfg, sf, smb_factory=lambda *_a, **_k: FakeSmb("D$"),
                    sleep_fn=lambda _seconds: None)):
            uc = {"id": "credential-access/sample-network-operation",
                  "rule_ids": ["r1"], "executor": "ad_network",
                  "params": {"operation": "ephemeral_computer_ntlm"}}
            result = ad_network(uc, Ctx(cfg=CFG, winrm_factory=factory))
        self.assertFalse(result.executed)
        self.assertNotEqual(result.status, "SUCCESS")
        self.assertTrue(result.status.startswith("ERROR: RuntimeError: computer cleanup was not proven after"))
        self.assertIn("residue may remain on the DC", result.status)
        self.assertEqual(factory.cleanup_calls, CLEANUP_ATTEMPTS)

    def test_every_winrm_script_fits_the_cmd_exe_limit(self):
        password = "Zy!" + "f" * 24 + "aA9"
        scripts = list(_ephemeral_computer_scripts("0123abcd", password))
        for state in ("Running", "Stopped"):
            for mode in ("Auto", "Manual", "Disabled"):
                scripts += _backup_scripts("0123abcd", password, state, mode)[1:]
        scripts += _failed_auth_scripts("0123abcd", password)[1:]
        scripts += _failed_burst_scripts("0123abcd", password)[1:]
        for script in scripts:
            self.assertLessEqual(run_ps_cmdline_len(script), MAX_RUN_PS_CMDLINE)


if __name__ == "__main__":
    unittest.main()
