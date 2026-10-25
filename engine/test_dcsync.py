import unittest
from unittest import mock

from ctx import Ctx
from executors.dcsync import (
    EPHEMERAL_ATTACK_MARKER, EPHEMERAL_CLEANUP_MARKER,
    EPHEMERAL_CLEANUP_ATTEMPTS, EPHEMERAL_PROBE_MARKER,
    _ephemeral_scripts, dcsync, dcsync_ephemeral, run_dcsync,
    run_ephemeral_dcsync,
)


class FakeSmb:
    instances = []

    def __init__(self, remote_name, remote_host, sess_port=445):
        self.remote_name = remote_name
        self.remote_host = remote_host
        self.sess_port = sess_port
        self.logged_off = False
        self.__class__.instances.append(self)

    def login(self, user, password, domain):
        self.login_args = (user, password, domain)

    def logoff(self):
        self.logged_off = True


class FakeRemote:
    instances = []

    def __init__(self, smb, kerberos):
        self.smb = smb
        self.kerberos = kerberos
        self.finished = False
        self.__class__.instances.append(self)

    def setExecMethod(self, method):
        self.method = method

    def finish(self):
        self.finished = True


class FakeNtds:
    instances = []

    def __init__(self, ntds_file, boot_key, **kwargs):
        self.kwargs = kwargs
        self.finished = False
        self.__class__.instances.append(self)

    def dump(self):
        # This string represents credential material. The implementation may count
        # it, but must never retain it in its return value or Result output.
        self.kwargs["perSecretCallback"]("NTDS", "krbtgt:500:HASH-MUST-NOT-LEAK")

    def finish(self):
        self.finished = True


CFG = {
    "target": "domain_controller", "win_host": "192.0.2.40",
    "win_user": "Administrator", "win_pass": "not-a-real-password",
    "dc_domain": "LAB", "dc_fqdn": "dc1.lab.invalid",
}


class Response:
    def __init__(self, out=b"", err=b"", code=0):
        self.std_out = out
        self.std_err = err
        self.status_code = code


class EphemeralFactory:
    def __init__(self, setup_code=0, probe=EPHEMERAL_PROBE_MARKER,
                 cleanup_failures=0, probe_failures=0,
                 failure_text="transient transport failure"):
        self.sessions = 0
        self.setup_code = setup_code
        self.probe = probe
        self.cleanup_failures = cleanup_failures
        self.probe_failures = probe_failures
        self.failure_text = failure_text
        self.scripts = []
        self.cleanup_calls = 0
        self.probe_calls = 0
        self.cleaned = False

    def __call__(self):
        self.sessions += 1
        outer = self

        class Session:
            def run_ps(self, script):
                outer.scripts.append(script)
                if EPHEMERAL_PROBE_MARKER in script:
                    outer.probe_calls += 1
                    if outer.probe_calls <= outer.probe_failures:
                        raise OSError(outer.failure_text)
                    value = (outer.probe if outer.cleaned else
                             "ZYBUR_EPHEMERAL_DCSYNC_RESIDUAL:user")
                    return Response((value + "\n").encode())
                if EPHEMERAL_CLEANUP_MARKER in script:
                    outer.cleanup_calls += 1
                    if outer.cleanup_calls <= outer.cleanup_failures:
                        raise OSError(outer.failure_text)
                    outer.cleaned = True
                    return Response((EPHEMERAL_CLEANUP_MARKER + ":S-1-5-21-1-2-3-1001\n").encode())
                return Response((EPHEMERAL_ATTACK_MARKER + ":S-1-5-21-1-2-3-1001\n").encode(),
                                b"setup failed" if outer.setup_code else b"",
                                outer.setup_code)

        return Session()


class TestDcsync(unittest.TestCase):
    def setUp(self):
        FakeSmb.instances.clear()
        FakeRemote.instances.clear()
        FakeNtds.instances.clear()

    def test_requests_one_account_and_discards_the_value(self):
        count = run_dcsync(CFG, "krbtgt", FakeSmb, FakeRemote, FakeNtds)
        self.assertEqual(count, 1)
        ntds = FakeNtds.instances[-1]
        self.assertEqual(ntds.kwargs["justUser"], "krbtgt")
        self.assertTrue(ntds.kwargs["justNTLM"])
        self.assertIsNone(ntds.kwargs["outputFileName"])
        self.assertTrue(ntds.finished)
        self.assertTrue(FakeRemote.instances[-1].finished)
        self.assertTrue(FakeSmb.instances[-1].logged_off)

    def test_executor_result_never_contains_the_secret_or_password(self):
        import executors.dcsync as mod
        original = mod.run_dcsync
        with mock.patch.object(
                mod, "run_dcsync",
                side_effect=lambda cfg, account: original(
                    cfg, account, FakeSmb, FakeRemote, FakeNtds)):
            uc = {"id": "credential-access/dcsync", "rule_ids": ["r1"],
                  "executor": "dcsync", "params": {"account": "krbtgt"}}
            result = dcsync(uc, Ctx(cfg=CFG))
        self.assertTrue(result.executed)
        self.assertTrue(FakeNtds.instances)
        self.assertNotIn("HASH-MUST-NOT-LEAK", result.output + result.status)
        self.assertNotIn(CFG["win_pass"], result.output + result.status)

    def test_executor_redacts_configured_password_from_errors(self):
        import executors.dcsync as mod
        with mock.patch.object(
                mod, "run_dcsync",
                side_effect=RuntimeError("authentication failed: " + CFG["win_pass"])):
            uc = {"id": "credential-access/dcsync", "rule_ids": ["r1"],
                  "executor": "dcsync", "params": {"account": "krbtgt"}}
            result = dcsync(uc, Ctx(cfg=CFG))
        self.assertFalse(result.executed)
        self.assertNotIn(CFG["win_pass"], result.output + result.status)
        self.assertIn("[REDACTED]", result.status)

    def test_rejects_an_injected_account_name(self):
        with self.assertRaisesRegex(ValueError, "simple AD account"):
            run_dcsync(CFG, "krbtgt; Remove-Item C:\\\\*", FakeSmb, FakeRemote, FakeNtds)

    def test_refuses_to_run_without_an_explicit_dc_target(self):
        with self.assertRaisesRegex(ValueError, "target: domain_controller"):
            run_dcsync(dict(CFG, target="workstation"), "krbtgt",
                       FakeSmb, FakeRemote, FakeNtds)

    def test_ephemeral_scripts_guard_owner_and_verify_dacl_removal(self):
        _, attack, cleanup, probe = _ephemeral_scripts(
            "0123abcd", "Ephemeral!aA9", sid="S-1-5-21-1-2-3-1001")
        for script in (attack, cleanup, probe):
            self.assertIn("Description -ne $owner", script)
            self.assertIn("refusing to touch a pre-existing AD user", script)
        self.assertIn("RemoveAccessRuleSpecific", cleanup)
        self.assertIn("replication right cleanup was not proven", cleanup)
        self.assertLess(
            cleanup.index("replication right cleanup was not proven"),
            cleanup.index("Remove-ADUser"),
        )
        self.assertIn("ZYBUR_EPHEMERAL_DCSYNC_RESIDUAL:rights", probe)

    def test_ephemeral_rejects_an_injected_token_before_opening_a_session(self):
        factory = EphemeralFactory()
        with self.assertRaisesRegex(ValueError, "lowercase hex"):
            run_ephemeral_dcsync(
                CFG, "krbtgt", factory, dcsync_fn=lambda *_: 1,
                token="x'; Remove-ADUser *", password="Ephemeral!aA9")
        self.assertEqual(factory.sessions, 0)

    def test_ephemeral_principal_is_used_then_three_session_cleanup_is_proven(self):
        factory = EphemeralFactory()
        calls = []

        def fake_dcsync(cfg, account):
            calls.append((cfg["win_user"], cfg["win_pass"], account))
            return 1

        summary = run_ephemeral_dcsync(
            CFG, "krbtgt", factory, dcsync_fn=fake_dcsync,
            token="0123abcd", password="Ephemeral!aA9")
        self.assertIn("cleanup independently proven", summary)
        self.assertEqual(factory.sessions, 3)
        self.assertEqual(calls[0][0], "zv-dcs-0123abcd")
        self.assertEqual(calls[0][2], "krbtgt")
        self.assertNotIn("Ephemeral!aA9", summary)

    def test_ephemeral_setup_failure_still_cleans_and_probes(self):
        factory = EphemeralFactory(setup_code=1)
        with self.assertRaisesRegex(RuntimeError, "setup exited"):
            run_ephemeral_dcsync(
                CFG, "krbtgt", factory, dcsync_fn=lambda *_: 1,
                token="0123abcd", password="Ephemeral!aA9")
        self.assertEqual(factory.sessions, 3)

    def test_ephemeral_cleanup_retries_with_fresh_sessions(self):
        factory = EphemeralFactory(cleanup_failures=2)
        replication_calls = []

        def fake_dcsync(*args):
            replication_calls.append(args)
            return 1

        summary = run_ephemeral_dcsync(
            CFG, "krbtgt", factory, dcsync_fn=fake_dcsync,
            token="0123abcd", password="Ephemeral!aA9", sleep_fn=lambda _: None)
        self.assertIn("cleanup independently proven", summary)
        self.assertEqual(len(replication_calls), 1)
        self.assertEqual(factory.cleanup_calls, EPHEMERAL_CLEANUP_ATTEMPTS)
        self.assertEqual(factory.probe_calls, EPHEMERAL_CLEANUP_ATTEMPTS)
        self.assertEqual(factory.sessions, 1 + (2 * EPHEMERAL_CLEANUP_ATTEMPTS))

    def test_ephemeral_probe_retries_with_fresh_sessions(self):
        factory = EphemeralFactory(probe_failures=2)
        run_ephemeral_dcsync(
            CFG, "krbtgt", factory, dcsync_fn=lambda *_: 1,
            token="0123abcd", password="Ephemeral!aA9", sleep_fn=lambda _: None)
        self.assertEqual(factory.cleanup_calls, EPHEMERAL_CLEANUP_ATTEMPTS)
        self.assertEqual(factory.probe_calls, EPHEMERAL_CLEANUP_ATTEMPTS)

    def test_ephemeral_persistent_cleanup_failure_is_redacted(self):
        password = "Ephemeral!aA9"
        factory = EphemeralFactory(
            cleanup_failures=EPHEMERAL_CLEANUP_ATTEMPTS,
            failure_text="transport exposed " + password,
        )
        with self.assertRaisesRegex(RuntimeError, "after 3 attempts") as raised:
            run_ephemeral_dcsync(
                CFG, "krbtgt", factory, dcsync_fn=lambda *_: 1,
                token="0123abcd", password=password, sleep_fn=lambda _: None)
        self.assertNotIn(password, str(raised.exception))
        self.assertIn("[REDACTED]", str(raised.exception))

    def test_ephemeral_executor_redacts_configured_secrets_from_errors(self):
        import executors.dcsync as mod
        cfg = dict(CFG, dc_pass="another-not-real-password")
        leaked = f"{cfg['win_pass']} / {cfg['dc_pass']}"
        with mock.patch.object(
                mod, "run_ephemeral_dcsync",
                side_effect=RuntimeError("cleanup failed: " + leaked)):
            uc = {"id": "credential-access/ephemeral-dcsync", "rule_ids": ["r1"],
                  "executor": "dcsync_ephemeral", "params": {"account": "krbtgt"}}
            result = dcsync_ephemeral(uc, Ctx(cfg=cfg, winrm_factory=EphemeralFactory()))
        self.assertFalse(result.executed)
        self.assertNotIn(cfg["win_pass"], result.output + result.status)
        self.assertNotIn(cfg["dc_pass"], result.output + result.status)
        self.assertEqual(result.status.count("[REDACTED]"), 2)

    def test_ephemeral_residual_fails_the_run(self):
        factory = EphemeralFactory(probe="ZYBUR_EPHEMERAL_DCSYNC_RESIDUAL:rights")
        with self.assertRaisesRegex(RuntimeError, "residual state"):
            run_ephemeral_dcsync(
                CFG, "krbtgt", factory, dcsync_fn=lambda *_: 1,
                token="0123abcd", password="Ephemeral!aA9", sleep_fn=lambda _: None)
        self.assertEqual(factory.probe_calls, EPHEMERAL_CLEANUP_ATTEMPTS)


if __name__ == "__main__":
    unittest.main()
