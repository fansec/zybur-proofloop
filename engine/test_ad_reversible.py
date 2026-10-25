import unittest

from ctx import Ctx
from executors.ad_reversible import (
    ATTACK_MARKER, CLEANUP_MARKER, PROBE_MARKER, OPERATIONS,
    ad_reversible, build_scripts, run_ad_reversible,
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
                if "Write-Output 'ZYBUR_AD_PROBE_CLEAN'" in script:
                    return outer.responses["probe"]
                if "Write-Output 'ZYBUR_AD_CLEANUP_OK'" in script:
                    return outer.responses["cleanup"]
                return outer.responses["attack"]

        return Session()


CFG = {
    "target": "domain_controller", "win_host": "192.0.2.40",
    "win_user": "Administrator", "win_pass": "not-a-real-password",
}


class TestScriptGeneration(unittest.TestCase):
    def test_every_operation_has_attack_cleanup_and_probe(self):
        for operation in OPERATIONS:
            attack, cleanup, probe = build_scripts(operation, "0123abcd")
            self.assertIn(ATTACK_MARKER, attack)
            self.assertIn(CLEANUP_MARKER, cleanup)
            self.assertIn(PROBE_MARKER, probe)
            self.assertIn("ErrorAction", attack)

    def test_operations_map_to_the_detection_relevant_ad_changes(self):
        needles = {
            "password_never_expires": "-PasswordNeverExpires $true",
            "preauth_disabled": "-DoesNotRequirePreAuth $true",
            "user_spn_added": "servicePrincipalName",
            "computer_dns_mismatch": "-DNSHostName $mismatch",
            "computer_sam_without_dollar": "@{sAMAccountName=$newSam}",
            "dns_record_created": "Add-DnsServerResourceRecordA",
            "dns_wpad_created": "-Name 'wpad'",
            "dns_wildcard_created": "-Name '*'",
            "dns_spn_coercion_created": "UWhRCzv0123abcdBAAAA",
            "dns_zone_export": "Export-DnsServerZone",
        }
        for operation, needle in needles.items():
            self.assertIn(needle, build_scripts(operation, "0123abcd")[0])

    def test_object_cleanup_is_owner_guarded(self):
        attack, cleanup, _ = build_scripts("user_spn_added", "0123abcd")
        for script in (attack, cleanup):
            self.assertIn("Description -ne", script)
            self.assertIn("refusing to touch a pre-existing AD object", script)

    def test_disposable_computer_accounts_are_explicitly_disabled(self):
        for operation in ("computer_dns_mismatch", "computer_sam_without_dollar"):
            attack, _, _ = build_scripts(operation, "0123abcd")
            self.assertIn("New-ADComputer", attack)
            self.assertIn("-Enabled $false", attack)

    def test_dns_record_zones_create_and_enforce_owner_markers(self):
        operations = {
            "dns_record_created", "dns_wpad_created", "dns_wildcard_created",
            "dns_spn_coercion_created",
        }
        for operation in operations:
            attack, cleanup, _ = build_scripts(operation, "0123abcd")
            self.assertIn(
                "Add-DnsServerResourceRecord -ZoneName $zone -Txt "
                "-Name '_zybur_owner'",
                attack,
            )
            for script in (attack, cleanup):
                self.assertIn("Assert-OwnedZone", script)
                self.assertIn("without its owner marker", script)
                self.assertIn(
                    "    Assert-OwnedZone\n"
                    "    Remove-DnsServerZone -Name $zone",
                    script,
                )
            self.assertLess(
                attack.index("\nRemove-OwnedZone\n"),
                attack.index("Add-DnsServerPrimaryZone"),
            )
            self.assertIn("elseif ($createdHere)", attack)

    def test_absence_probe_uses_zero_result_ldap_query(self):
        """Get-AD* -Identity emits ADIdentityNotFoundException for the clean state."""
        for operation in {op for op in OPERATIONS if not op.startswith("dns_")}:
            attack, cleanup, probe = build_scripts(operation, "0123abcd")
            self.assertIn("-LDAPFilter", cleanup)
            self.assertIn("-LDAPFilter", probe)
            self.assertNotIn("-Identity 'ZV", probe)
            self.assertNotIn("-Identity 'zv-", probe)

    def test_unknown_operation_and_injected_token_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "unknown reversible"):
            build_scripts("arbitrary_powershell", "0123abcd")
        with self.assertRaisesRegex(ValueError, "lowercase hex"):
            build_scripts("preauth_disabled", "x'; Remove-ADUser *")

    def test_dns_export_cleanup_requires_owner_markers(self):
        attack, cleanup, probe = build_scripts("dns_zone_export", "0123abcd")
        for script in (attack, cleanup):
            self.assertIn("Assert-OwnedZone", script)
            self.assertIn("without its owner marker", script)
        self.assertIn("dns-export:0123abcd", probe)


class TestExecution(unittest.TestCase):
    def test_success_uses_three_sessions_and_proves_cleanup(self):
        factory = FakeFactory()
        summary = run_ad_reversible(
            CFG, "password_never_expires", factory, token="0123abcd")
        self.assertIn("cleanup independently proven", summary)
        self.assertEqual(factory.sessions, 3)

    def test_attack_failure_still_runs_cleanup_and_probe(self):
        factory = FakeFactory(attack=Response(err=b"mutation failed", code=1))
        with self.assertRaisesRegex(RuntimeError, "mutation exited"):
            run_ad_reversible(CFG, "preauth_disabled", factory, token="0123abcd")
        self.assertEqual(factory.sessions, 3)

    def test_residual_state_fails_the_run(self):
        factory = FakeFactory(probe=Response(b"ZYBUR_AD_RESIDUAL:user:zv-ne-0123abcd\n"))
        with self.assertRaisesRegex(RuntimeError, "residual state"):
            run_ad_reversible(
                CFG, "password_never_expires", factory, token="0123abcd")

    def test_workstation_target_is_refused(self):
        with self.assertRaisesRegex(ValueError, "target: domain_controller"):
            run_ad_reversible(
                dict(CFG, target="workstation"), "preauth_disabled", FakeFactory(),
                token="0123abcd")

    def test_result_never_echoes_the_password(self):
        factory = FakeFactory(attack=Response(err=CFG["win_pass"].encode(), code=1))
        uc = {"id": "credential-access/preauth", "rule_ids": ["r1"],
              "executor": "ad_reversible", "params": {"operation": "preauth_disabled"}}
        result = ad_reversible(uc, Ctx(cfg=CFG, winrm_factory=factory))
        self.assertFalse(result.executed)
        self.assertNotIn(CFG["win_pass"], result.status + result.output)


if __name__ == "__main__":
    unittest.main()
