# rules/engine/test_migrate.py
import unittest
from migrate_from_yaml import map_test, map_executor, _slug

PSH = {"num": 1, "rule": "LSASS Memory Dump Creation", "severity": "HIGH", "group": "cred",
       "tactic": "credential-access", "technique_id": "T1003.001",
       "technique_name": "OS Credential Dumping: LSASS Memory",
       "attack": "Dump LSASS process memory via comsvcs.dll MiniDump — extracts hashes",
       "executor": "psh", "command": "$x = whoami", "cleanup": "Remove-Item x"}

SMB_RENAME = {"num": 8, "rule": "Sample SMB Rename Rule", "severity": "HIGH", "group": "impact",
              "tactic": "impact", "technique_id": "T1486", "technique_name": "Data Encrypted for Impact",
              "attack": "Rename many files over SMB — ransomware mass-rename",
              "executor": "DIRECT_SMB_RENAME", "command": "", "cleanup": ""}

class TestMigrate(unittest.TestCase):
    def test_psh_maps_to_caldera_command(self):
        uc = map_test(PSH)
        self.assertEqual(uc["executor"], "caldera_command")
        self.assertEqual(uc["id"], "credential-access/lsass-memory-dump-creation")
        self.assertEqual(uc["params"]["shell"], "psh")
        self.assertEqual(uc["rules"], ["LSASS Memory Dump Creation"])
        self.assertNotIn("—", uc["description"])  # long dash sanitized
    def test_direct_smb_rename_maps_to_plugin(self):
        uc = map_test(SMB_RENAME)
        self.assertEqual(uc["executor"], "smb_rename")
        self.assertEqual(uc["id"], "impact/sample-smb-rename-rule")
    def test_winrm_num_overrides(self):
        self.assertEqual(map_executor("DIRECT_WINRM", 33), "psremoting")
        self.assertEqual(map_executor("DIRECT_WINRM", 21), "rdp_keystroke")
        self.assertEqual(map_executor("DIRECT_WINRM", 45), "rdp_keystroke")
        self.assertEqual(map_executor("DIRECT_WINRM", 23), "hidden_user")
        self.assertEqual(map_executor("DIRECT_WINRM", 4), "winrm_command")
    def test_slug(self):
        self.assertEqual(_slug("LSASS Memory Dump Creation"), "lsass-memory-dump-creation")

if __name__ == "__main__":
    unittest.main()
