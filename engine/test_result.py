# rules/engine/test_result.py
import unittest
from result import Verdict, Result, make_result

class TestResult(unittest.TestCase):
    def test_make_result_from_usecase(self):
        uc = {"id": "c/x", "rule_ids": ["r1"], "executor": "caldera_command"}
        r = make_result(uc, "SUCCESS", True, op_id="op1")
        self.assertEqual(r.id, "c/x")
        self.assertEqual(r.rule_ids, ["r1"])
        self.assertTrue(r.executed)
    def test_to_dict_serializes_verdict_name(self):
        uc = {"id": "c/x", "rule_ids": [], "executor": "e"}
        r = make_result(uc, "SUCCESS", True, verdict=Verdict.DETECTED)
        self.assertEqual(r.to_dict()["verdict"], "DETECTED")
    def test_to_dict_null_verdict(self):
        uc = {"id": "c/x", "rule_ids": [], "executor": "e"}
        self.assertIsNone(make_result(uc, "X", False).to_dict()["verdict"])

if __name__ == "__main__":
    unittest.main()
