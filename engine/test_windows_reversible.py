import unittest

from ctx import Ctx
from executors.windows_reversible import (
    ATTACK_MARKER, CLEANUP_MARKER, PROBE_MARKER, OPERATIONS,
    NIGHTLY_SAFE_OPERATIONS, build_scripts, run_windows_reversible,
    windows_reversible,
)


class Response:
    def __init__(self, out=b"", err=b"", code=0):
        self.std_out = out
        self.std_err = err
        self.status_code = code


class FakeFactory:
    def __init__(self, attack=None, cleanup=None, probe=None, audit_enabled=True):
        self.responses = {
            "attack": attack or Response((ATTACK_MARKER + "\n").encode()),
            "cleanup": cleanup or Response((CLEANUP_MARKER + "\n").encode()),
            "probe": probe or Response((PROBE_MARKER + "\n").encode()),
        }
        self.scripts = []
        self.sessions = 0
        self.audit_enabled = audit_enabled

    def __call__(self):
        self.sessions += 1
        outer = self

        class Session:
            def run_cmd(self, command, args):
                outer.scripts.append(" ".join([command, *args]))
                setting = "Success" if outer.audit_enabled else "No Auditing"
                return Response((f"DC1,System,Token Right Adjusted Events,GUID,{setting},\n").encode())

            def run_ps(self, script):
                outer.scripts.append(script)
                if PROBE_MARKER in script:
                    return outer.responses["probe"]
                if CLEANUP_MARKER in script:
                    return outer.responses["cleanup"]
                return outer.responses["attack"]

        return Session()


CFG = {
    "target": "domain_controller", "win_host": "192.0.2.40",
    "win_user": "Administrator", "win_pass": "not-a-real-password",
}


class TestScriptGeneration(unittest.TestCase):
    def test_every_operation_has_attack_cleanup_and_probe(self):
        self.assertEqual(OPERATIONS, NIGHTLY_SAFE_OPERATIONS)
        self.assertEqual(len(OPERATIONS), 12)
        for operation in OPERATIONS:
            attack, cleanup, probe = build_scripts(operation, "0123abcd")
            self.assertIn(ATTACK_MARKER, attack)
            self.assertIn(CLEANUP_MARKER, cleanup)
            self.assertIn(PROBE_MARKER, probe)
            self.assertIn("ErrorAction", attack)

    def test_operations_emit_detection_relevant_behavior(self):
        needles = {
            "endpoint_behavior_alert": "ZyburRenamedPowerShell.exe",
            "genai_config_modify": "cscript.exe",
            "genai_sensitive_file_access": "ollama.exe",
            "msbuild_script_parent": "parent.proj",
            "msbuild_unusual_child": "System.Diagnostics.Process.Start",
            "msbuild_vaultcli_load": "vaultcli.dll",
            "privileged_group_enumeration": "NetLocalGroupGetMembers",
            "remote_service_install": "sc.exe create",
            "scheduled_task_update": "Set-ScheduledTask",
            "sedebug_privilege_enable": "SeDebugPrivilege",
            "unsigned_service_execute": "New-Service",
            "wdac_inert_policy_file": "CodeIntegrity",
        }
        for operation, needle in needles.items():
            self.assertIn(needle, build_scripts(operation, "0123abcd")[0])

    def test_stateful_names_are_random_token_scoped(self):
        for operation in OPERATIONS:
            attack, cleanup, probe = build_scripts(operation, "0123abcd")
            joined = attack + cleanup + probe
            self.assertIn("0123abcd", joined)

    def test_unknown_operation_and_injected_token_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "unknown managed Windows"):
            build_scripts("arbitrary_powershell", "0123abcd")
        with self.assertRaisesRegex(ValueError, "lowercase hex"):
            build_scripts("scheduled_task_update", "x'; Remove-Item C:\\*")

    def test_unsigned_service_and_wdac_cleanup_are_owner_guarded(self):
        attack, cleanup, _ = build_scripts("unsigned_service_execute", "0123abcd")
        for script in (attack, cleanup):
            self.assertIn("Assert-OwnedRoot", script)
            self.assertIn("different binary path", script)
        attack, cleanup, _ = build_scripts("wdac_inert_policy_file", "0123abcd")
        for script in (attack, cleanup):
            self.assertIn("different content", script)

    def test_genai_sensitive_read_uses_only_an_owned_synthetic_file(self):
        attack, cleanup, probe = build_scripts(
            "genai_sensitive_file_access", "0123abcd")
        for script in (attack, cleanup, probe):
            self.assertIn(
                r"Microsoft\Credentials\ZyburValidation-0123abcd", script)
        self.assertIn("Join-Path $root 'credentials.db'", attack)
        self.assertIn("System32\\whoami.exe", attack)
        self.assertIn("Process.Start", attack)
        self.assertIn("Remove-OwnedRoot", cleanup)


class TestExecution(unittest.TestCase):
    def test_success_uses_three_sessions_and_proves_cleanup(self):
        factory = FakeFactory()
        summary = run_windows_reversible(
            CFG, "scheduled_task_update", factory, token="0123abcd")
        self.assertIn("cleanup independently proven", summary)
        self.assertEqual(factory.sessions, 3)

    def test_attack_failure_still_runs_cleanup_and_probe(self):
        factory = FakeFactory(attack=Response(err=b"operation failed", code=1))
        with self.assertRaisesRegex(RuntimeError, "operation exited"):
            run_windows_reversible(
                CFG, "genai_config_modify", factory, token="0123abcd")
        self.assertEqual(factory.sessions, 3)

    def test_sedebug_requires_token_right_auditing_before_attack(self):
        factory = FakeFactory(audit_enabled=False)
        with self.assertRaisesRegex(RuntimeError, "success auditing is not enabled"):
            run_windows_reversible(
                CFG, "sedebug_privilege_enable", factory, token="0123abcd")
        self.assertEqual(factory.sessions, 3)
        self.assertFalse(any(ATTACK_MARKER in script for script in factory.scripts))

    def test_residual_state_fails_the_run(self):
        factory = FakeFactory(probe=Response(
            b"ZYBUR_WINDOWS_REVERSIBLE_RESIDUAL:root:test\n"))
        with self.assertRaisesRegex(RuntimeError, "residual state"):
            run_windows_reversible(
                CFG, "msbuild_script_parent", factory, token="0123abcd")

    def test_unknown_target_is_refused(self):
        with self.assertRaisesRegex(ValueError, "registered Windows target"):
            run_windows_reversible(
                dict(CFG, target="linux"), "scheduled_task_update", FakeFactory(),
                token="0123abcd")

    def test_registered_handler_returns_a_result(self):
        factory = FakeFactory()
        uc = {"id": "persistence/task-update", "rule_ids": ["r1"],
              "executor": "windows_reversible",
              "params": {"operation": "scheduled_task_update"}}
        result = windows_reversible(uc, Ctx(cfg=CFG, winrm_factory=factory))
        self.assertTrue(result.executed)
        self.assertEqual(result.status, "SUCCESS")


if __name__ == "__main__":
    unittest.main()
