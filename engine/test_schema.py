# rules/engine/test_schema.py
import unittest
from schema import validate_usecase

BASE = {
    "id": "credential-access/lsass", "title": "LSASS dump",
    "rules": ["LSASS Memory Dump Creation"], "technique": "T1003.001",
    "tactic": "credential-access", "executor": "caldera_command",
    "params": {"shell": "psh", "command": "whoami"},
    "safety": "safe", "cleanup": "Remove-Item z",
}
# A path that matches BASE["id"] (id must equal path minus .yaml).
BASE_PATH = "credential-access/lsass.yaml"

class TestSchema(unittest.TestCase):
    def test_valid_usecase(self):
        self.assertEqual(validate_usecase(dict(BASE), BASE_PATH), [])
    def test_missing_required_field(self):
        d = dict(BASE); del d["technique"]
        errs = validate_usecase(d, BASE_PATH)
        self.assertTrue(any("technique" in e for e in errs))
    def test_id_must_match_path(self):
        d = dict(BASE)
        errs = validate_usecase(d, "impact/other.yaml")
        self.assertTrue(any("id" in e and "path" in e for e in errs))
    def test_bad_technique_id(self):
        d = dict(BASE); d["technique"] = "TXXXX"
        self.assertTrue(any("technique" in e for e in validate_usecase(d, BASE_PATH)))
    def test_additional_techniques_are_validated(self):
        d = dict(BASE); d["additional_techniques"] = ["T1550.002"]
        self.assertEqual(validate_usecase(d, BASE_PATH), [])
        d["additional_techniques"] = ["not-a-technique"]
        self.assertTrue(any("additional technique" in e for e in validate_usecase(d, BASE_PATH)))
    def test_additional_techniques_must_not_repeat_primary(self):
        d = dict(BASE); d["additional_techniques"] = [d["technique"]]
        self.assertTrue(any("must not repeat" in e for e in validate_usecase(d, BASE_PATH)))
    def test_rules_may_be_empty_only_for_env_gap(self):
        d = dict(BASE); d["rules"] = []; d["expect"] = "env_gap"
        self.assertEqual(validate_usecase(d, BASE_PATH), [])
        d2 = dict(BASE); d2["rules"] = []
        self.assertTrue(validate_usecase(d2, BASE_PATH))
    def test_bad_expect_value(self):
        d = dict(BASE); d["expect"] = "maybe"
        self.assertTrue(any("expect" in e for e in validate_usecase(d, BASE_PATH)))
    def test_long_dash_in_authored_string_rejected(self):
        d = dict(BASE); d["title"] = "LSASS — dump"
        self.assertTrue(any("dash" in e for e in validate_usecase(d, BASE_PATH)))
    def test_safety_is_required(self):
        d = dict(BASE); del d["safety"]
        self.assertTrue(any("safety" in e for e in validate_usecase(d, BASE_PATH)))
    def test_safety_value_must_be_valid(self):
        d = dict(BASE); d["safety"] = "maybe"
        self.assertTrue(any("safety" in e for e in validate_usecase(d, BASE_PATH)))
    def test_target_defaults_to_workstation_and_accepts_domain_controller(self):
        self.assertEqual(validate_usecase(dict(BASE), BASE_PATH), [])
        d = dict(BASE); d["target"] = "domain_controller"
        self.assertEqual(validate_usecase(d, BASE_PATH), [])
    def test_unknown_target_is_rejected(self):
        d = dict(BASE); d["target"] = "customer"
        self.assertTrue(any("target" in e for e in validate_usecase(d, BASE_PATH)))
    def test_destroys_evidence_must_be_boolean(self):
        d = dict(BASE); d["destroys_evidence"] = "yes"
        self.assertTrue(any("destroys_evidence" in e for e in validate_usecase(d, BASE_PATH)))
    def test_leaves_no_artifact_must_be_boolean(self):
        d = dict(BASE); d["leaves_no_artifact"] = "yes"
        self.assertTrue(any("leaves_no_artifact" in e for e in validate_usecase(d, BASE_PATH)))
    def test_leaves_no_artifact_contradicts_a_cleanup(self):
        d = dict(BASE); d["leaves_no_artifact"] = True; d["cleanup"] = "Remove-Item x"
        self.assertTrue(any("contradicts" in e for e in validate_usecase(d, BASE_PATH)))
    def test_leaves_no_artifact_alone_is_valid(self):
        d = dict(BASE); d["leaves_no_artifact"] = True; d.pop("cleanup", None)
        self.assertEqual([e for e in validate_usecase(d, BASE_PATH)
                          if "leaves_no_artifact" in e], [])
    def test_managed_cleanup_must_name_the_executor(self):
        d = dict(BASE); d.pop("cleanup", None); d["cleanup_managed_by"] = "other"
        self.assertTrue(any("cleanup_managed_by" in e for e in validate_usecase(d, BASE_PATH)))
    def test_managed_cleanup_cannot_claim_two_cleanup_models(self):
        d = dict(BASE); d["cleanup_managed_by"] = d["executor"]
        self.assertTrue(any("contradicts" in e for e in validate_usecase(d, BASE_PATH)))
    def test_managed_cleanup_alone_is_schema_valid(self):
        d = dict(BASE); d.pop("cleanup", None); d["cleanup_managed_by"] = d["executor"]
        self.assertEqual(validate_usecase(d, BASE_PATH), [])

    # P-D1: evidence is optional at the schema level (lint.py is where it becomes
    # required, and only for safe-pool members) but validated in shape when present.
    def test_evidence_is_optional(self):
        d = dict(BASE)
        self.assertNotIn("evidence", d)
        self.assertEqual(validate_usecase(d, BASE_PATH), [])
    def test_evidence_valid_values_pass(self):
        for v in ("real_behaviour", "stand_in"):
            d = dict(BASE); d["evidence"] = v
            self.assertEqual(validate_usecase(d, BASE_PATH), [])
    def test_evidence_invalid_value_rejected(self):
        d = dict(BASE); d["evidence"] = "maybe"
        self.assertTrue(any("evidence" in e for e in validate_usecase(d, BASE_PATH)))

if __name__ == "__main__":
    unittest.main()
