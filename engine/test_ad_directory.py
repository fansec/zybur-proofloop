import hashlib
import unittest

from ctx import Ctx
from executors.ad_directory import (
    ATTACK_MARKER, CLEANUP_MARKER, PROBE_MARKER, OPERATIONS,
    NIGHTLY_SAFE_OPERATIONS, ad_directory, build_scripts, run_ad_directory,
    _secondary_logon_source,
)


class Response:
    def __init__(self, out=b"", err=b"", code=0):
        self.std_out = out
        self.std_err = err
        self.status_code = code


class FakeFactory:
    def __init__(self, attack=None, cleanup=None, probe=None):
        self.responses = {
            "attack": attack or Response((ATTACK_MARKER + "\n").encode()),
            "cleanup": cleanup or Response((CLEANUP_MARKER + "\n").encode()),
            "probe": probe or Response((PROBE_MARKER + "\n").encode()),
        }
        self.scripts = []
        self.sessions = 0

    def __call__(self):
        self.sessions += 1
        outer = self

        class Session:
            def run_ps(self, script):
                outer.scripts.append(script)
                if "Get-FileHash" in script and "ZyburSecondaryLogon" in script:
                    digest = hashlib.sha256(_secondary_logon_source().encode()).hexdigest().upper()
                    return Response((digest + "\n").encode())
                if "Write-Output 'ZYBUR_AD_DIRECTORY_PROBE_CLEAN'" in script:
                    return outer.responses["probe"]
                if "Write-Output 'ZYBUR_AD_DIRECTORY_CLEANUP_OK'" in script:
                    return outer.responses["cleanup"]
                return outer.responses["attack"]

        return Session()


CFG = {
    "target": "domain_controller", "win_host": "192.0.2.40",
    "win_user": "Administrator", "win_pass": "not-a-real-password",
    "dc_domain": "EXAMPLE",
}


class TestScriptGeneration(unittest.TestCase):
    def test_every_operation_has_attack_cleanup_and_probe(self):
        self.assertEqual(len(OPERATIONS), 19)
        for operation in OPERATIONS:
            attack, cleanup, probe = build_scripts(operation, "0123abcd")
            self.assertIn(ATTACK_MARKER, attack)
            self.assertIn(CLEANUP_MARKER, cleanup)
            self.assertIn(PROBE_MARKER, probe)
            self.assertIn("ErrorAction", attack)

    def test_operations_emit_detection_relevant_changes(self):
        needles = {
            "user_delegation_krbtgt": "msDS-AllowedToDelegateTo",
            "privileged_group_member_added": "AdminZV0123abcd",
            "shadow_credential_added": "msDS-KeyCredentialLink",
            "mspki_credentials_added": "msPKIAccountCredentials",
            "sensitive_attribute_read": "ReadProperty",
            "bulk_attribute_read": "-Properties *",
            "writedac_access": "WriteDacl",
            "replication_rights_added": "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2",
            "gpo_group_privilege": "827D319E-6EAC-11D2-A4EA-00C04F79F83A",
            "gpo_scheduled_task": "CAB54552-DEEA-4691-817E-ED4A4D1AFC72",
            "gpo_startup_script": "42B5FAAE-6536-11D2-AE5A-0000F87571E3",
            "system_group_member_added": "Register-ScheduledTask",
            "adminsdholder_reference_added": "CN=AdminSDHolder",
            "dsheuristics_exclusion_added": "dSHeuristics",
            "local_kerberos_service_created": "New-PSSession -ComputerName $fqdn -Authentication Kerberos",
            "delegation_privilege_assigned": "SeEnableDelegationPrivilege",
            "remote_password_reset": "Set-ADAccountPassword",
            "secondary_logon": "ZyburSecondaryLogon]::Run",
            "advapi_newcredentials": "ZyburSecondaryLogon]::LogonOnly",
        }
        for operation, needle in needles.items():
            self.assertIn(needle, build_scripts(operation, "0123abcd")[0])
        self.assertIn("CreateProcessWithLogonW", _secondary_logon_source())

    def test_nightly_set_excludes_real_protected_or_privileged_objects(self):
        self.assertNotIn("adminsdholder_reference_added", NIGHTLY_SAFE_OPERATIONS)
        self.assertNotIn("dsheuristics_exclusion_added", NIGHTLY_SAFE_OPERATIONS)
        self.assertNotIn("delegation_privilege_assigned", NIGHTLY_SAFE_OPERATIONS)
        self.assertIn("remote_password_reset", NIGHTLY_SAFE_OPERATIONS)
        self.assertIn("secondary_logon", NIGHTLY_SAFE_OPERATIONS)
        self.assertIn("advapi_newcredentials", NIGHTLY_SAFE_OPERATIONS)
        self.assertLess(NIGHTLY_SAFE_OPERATIONS, OPERATIONS)

    def test_unknown_operation_and_injected_token_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "unknown managed AD"):
            build_scripts("arbitrary_powershell", "0123abcd")
        with self.assertRaisesRegex(ValueError, "lowercase hex"):
            build_scripts("shadow_credential_added", "x'; Remove-ADUser *")


class TestExecution(unittest.TestCase):
    def test_success_uses_three_sessions_and_proves_cleanup(self):
        factory = FakeFactory()
        summary = run_ad_directory(
            CFG, "shadow_credential_added", factory, token="0123abcd")
        self.assertIn("cleanup independently proven", summary)
        self.assertEqual(factory.sessions, 3)

    def test_attack_failure_still_runs_cleanup_and_probe(self):
        factory = FakeFactory(attack=Response(err=b"mutation failed", code=1))
        with self.assertRaisesRegex(RuntimeError, "operation exited"):
            run_ad_directory(
                CFG, "bulk_attribute_read", factory, token="0123abcd")
        self.assertEqual(factory.sessions, 3)

    def test_residual_state_fails_the_run(self):
        factory = FakeFactory(probe=Response(
            b"ZYBUR_AD_DIRECTORY_RESIDUAL:user:zv-key-0123abcd\n"))
        with self.assertRaisesRegex(RuntimeError, "residual state"):
            run_ad_directory(
                CFG, "shadow_credential_added", factory, token="0123abcd")

    def test_workstation_target_is_refused(self):
        with self.assertRaisesRegex(ValueError, "target: domain_controller"):
            run_ad_directory(
                dict(CFG, target="workstation"), "shadow_credential_added",
                FakeFactory(), token="0123abcd")

    def test_result_never_echoes_password(self):
        factory = FakeFactory(attack=Response(err=CFG["win_pass"].encode(), code=1))
        uc = {"id": "credential-access/shadow", "rule_ids": ["r1"],
              "executor": "ad_directory",
              "params": {"operation": "shadow_credential_added"}}
        result = ad_directory(uc, Ctx(cfg=CFG, winrm_factory=factory))
        self.assertFalse(result.executed)
        self.assertNotIn(CFG["win_pass"], result.status + result.output)

    def test_secondary_logon_injects_credentials_only_at_runtime(self):
        factory = FakeFactory()
        run_ad_directory(CFG, "secondary_logon", factory, token="0123abcd")
        attack = next(s for s in factory.scripts if "ZyburSecondaryLogon]::Run" in s)
        self.assertNotIn("{{ZYBUR_DC_PASS_B64}}", attack)
        self.assertNotIn(CFG["win_pass"], attack)


if __name__ == "__main__":
    unittest.main()
