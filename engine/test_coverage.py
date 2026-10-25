# rules/engine/test_coverage.py
import contextlib, io, os, unittest
from coverage import join, worklist, check

HERE = os.path.dirname(__file__)
EXPORT = os.path.join(HERE, "fixtures", "rules_export.sample.ndjson")
class TestCoverage(unittest.TestCase):
    def test_join_marks_covered_and_uncovered(self):
        ucs = [{"id": "impact/shadow", "rule_ids": ["ba1b12cd-0000-0000-0000-000000000002"],
                "rules": ["Sample Rule Two"], "technique": "T1490",
                "expect": "detected"}]
        rep = join(ucs, EXPORT)
        covered_ids = {r["rule_id"] for r in rep["covered"]}
        uncovered_ids = {r["rule_id"] for r in rep["uncovered"]}
        self.assertIn("ba1b12cd-0000-0000-0000-000000000002", covered_ids)
        self.assertIn("ba1b12cd-0000-0000-0000-000000000001", uncovered_ids)  # LSASS untested
    def test_check_fails_when_gap(self):
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(check([], EXPORT), 1)

if __name__ == "__main__":
    unittest.main()
