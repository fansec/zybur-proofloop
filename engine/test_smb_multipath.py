import unittest

from ctx import Ctx
from executors.smb_multipath import (
    ATTACK_MARKER, CLEANUP_MARKER, PROBE_MARKER, OPERATIONS,
    build_remote_execute_scripts, build_scripts, run_smb_multipath,
    run_smb_remote_execute, smb_multipath,
)


class Response:
    def __init__(self, out=b"", err=b"", code=0):
        self.std_out = out
        self.std_err = err
        self.status_code = code


class FakeFactory:
    def __init__(self, residual=False):
        self.sessions = 0
        self.residual = residual
        self.scripts = []

    def __call__(self):
        self.sessions += 1
        outer = self

        class Session:
            def run_ps(self, script):
                outer.scripts.append(script)
                if PROBE_MARKER in script:
                    value = "ZYBUR_SMB_MULTIPATH_RESIDUAL:test" if outer.residual else PROBE_MARKER
                    return Response((value + "\n").encode())
                if ATTACK_MARKER in script:
                    return Response((ATTACK_MARKER + "\n").encode())
                return Response((CLEANUP_MARKER + "\n").encode())

        return Session()


class FakeSmb:
    def __init__(self):
        self.dirs = []
        self.files = []
        self.logged_off = False

    def createDirectory(self, share, path):
        self.dirs.append((share, path))

    def putFile(self, share, path, reader):
        self.files.append((share, path, reader()))

    def logoff(self):
        self.logged_off = True


CFG = {
    "target": "domain_controller", "win_host": "192.0.2.40",
    "win_user": "Administrator", "win_pass": "not-a-real-password",
    "dc_domain": "EXAMPLE", "dc_fqdn": "dc1.example.invalid",
}


class TestSmbMultipath(unittest.TestCase):
    def test_closed_operation_set_includes_remote_execution(self):
        self.assertEqual(OPERATIONS, {"multipath_note", "remote_execute"})

    def test_paths_are_token_owned_and_probe_is_independent(self):
        filename, roots, owner, cleanup, probe = build_scripts("0123abcd")
        self.assertEqual(len(roots), 3)
        self.assertTrue(all("0123abcd" in root for root in roots))
        self.assertIn("0123abcd", filename)
        self.assertIn(owner, cleanup)
        self.assertIn(PROBE_MARKER, probe)

    def test_one_filename_is_written_to_three_paths(self):
        factory, smb = FakeFactory(), FakeSmb()
        summary = run_smb_multipath(
            CFG, "multipath_note", factory, token="0123abcd",
            smb_factory=lambda _cfg: smb)
        self.assertEqual(factory.sessions, 3)
        self.assertEqual(len(smb.files), 3)
        self.assertEqual(len({path.rsplit("\\", 1)[-1] for _, path, _ in smb.files}), 1)
        self.assertTrue(smb.logged_off)
        self.assertIn("cleanup independently proven", summary)

    def test_residual_state_fails(self):
        with self.assertRaisesRegex(RuntimeError, "residual state"):
            run_smb_multipath(
                CFG, "multipath_note", FakeFactory(residual=True), token="0123abcd",
                smb_factory=lambda _cfg: FakeSmb())

    def test_remote_execute_uploads_runs_and_proves_absence(self):
        factory, smb = FakeFactory(), FakeSmb()
        summary = run_smb_remote_execute(
            CFG, factory, token="0123abcd", smb_factory=lambda _cfg: smb,
            payload_builder=lambda owner: b"MZ" + owner.encode())
        self.assertEqual(factory.sessions, 4)
        self.assertEqual(len(smb.files), 1)
        self.assertEqual(smb.files[0][1], r"Windows\Temp\ZyburRemoteExec-0123abcd.exe")
        self.assertTrue(smb.logged_off)
        self.assertTrue(any(ATTACK_MARKER in script for script in factory.scripts))
        self.assertIn("independently removed", summary)

    def test_remote_execute_cleanup_is_hash_guarded(self):
        _, _, cleanup, probe = build_remote_execute_scripts("0123abcd", "a" * 64)
        self.assertIn("different hash", cleanup)
        self.assertIn("0123abcd", probe)

    def test_registered_handler_redacts_password(self):
        import executors.smb_multipath as mod
        original = mod.run_smb_multipath
        mod.run_smb_multipath = lambda *_args, **_kwargs: (_ for _ in ()).throw(
            RuntimeError(CFG["win_pass"]))
        try:
            uc = {"id": "impact/note", "rule_ids": ["r1"],
                  "executor": "smb_multipath", "params": {"operation": "multipath_note"}}
            result = smb_multipath(uc, Ctx(cfg=CFG, winrm_factory=FakeFactory()))
        finally:
            mod.run_smb_multipath = original
        self.assertFalse(result.executed)
        self.assertNotIn(CFG["win_pass"], result.status)


if __name__ == "__main__":
    unittest.main()
