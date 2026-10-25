import unittest

import testenv
from config import config_for_target, missing_for_target
from labhosts import LabHostsError
from run import target_host


def setUpModule():
    testenv.use_fixture_lab_hosts_for_module()


CFG = {
    "win_host": "192.0.2.87", "win_user": "local-admin", "win_pass": "work-pass",
    "dc_host": "192.0.2.40", "dc_user": "domain-admin", "dc_pass": "dc-pass",
    "dc_domain": "LAB", "dc_fqdn": "dc1.lab.invalid",
}


class TestConfigTargets(unittest.TestCase):
    def test_workstation_is_the_default_and_keeps_winrm_values(self):
        got = config_for_target(CFG)
        self.assertEqual(got["target"], "workstation")
        self.assertEqual(got["win_host"], CFG["win_host"])
        self.assertEqual(got["win_pass"], CFG["win_pass"])

    def test_dc_projects_its_credentials_onto_the_executor_interface(self):
        got = config_for_target(CFG, "domain_controller")
        self.assertEqual(got["target"], "domain_controller")
        self.assertEqual(got["win_host"], CFG["dc_host"])
        self.assertEqual(got["win_user"], CFG["dc_user"])
        self.assertEqual(got["win_pass"], CFG["dc_pass"])

    def test_missing_dc_password_is_named_not_returned(self):
        cfg = dict(CFG, dc_pass=None)
        self.assertEqual(missing_for_target(cfg, "domain_controller"), ["DC_PASS"])

    def test_unknown_target_fails(self):
        with self.assertRaisesRegex(ValueError, "unknown use-case target"):
            config_for_target(CFG, "customer")

    def test_target_host_resolves_the_registered_dc(self):
        got = target_host(config_for_target(CFG, "domain_controller"), "domain_controller")
        self.assertEqual(got["name"], "dc1")
        self.assertIn("DC1.lab.invalid", got["aliases"])

    def test_unregistered_address_is_rejected_before_execution(self):
        with self.assertRaisesRegex(LabHostsError, "not registered"):
            target_host({"win_host": "203.0.113.99"}, "domain_controller")

    def test_role_mismatch_is_rejected(self):
        with self.assertRaisesRegex(LabHostsError, "belongs to role workstation"):
            target_host({"win_host": CFG["win_host"]}, "domain_controller")


if __name__ == "__main__":
    unittest.main()
