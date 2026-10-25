# rules/engine/test_ledger.py
import os, tempfile, unittest
from ledger import append, read, last_verdict
from run import _ledger_row
from result import Result, Verdict

class TestLedger(unittest.TestCase):
    def setUp(self):
        self.p = tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False).name
    def tearDown(self):
        os.unlink(self.p)
    def test_append_and_read(self):
        append(self.p, [{"id": "c/x", "run_ts": "2026-07-25T00:00:00", "verdict": "MISSED"}])
        append(self.p, [{"id": "c/x", "run_ts": "2026-07-26T00:00:00", "verdict": "DETECTED"}])
        self.assertEqual(len(read(self.p)), 2)
    def test_last_verdict_is_most_recent(self):
        append(self.p, [{"id": "c/x", "run_ts": "2026-07-25T00:00:00", "verdict": "MISSED"}])
        append(self.p, [{"id": "c/x", "run_ts": "2026-07-26T00:00:00", "verdict": "DETECTED"}])
        self.assertEqual(last_verdict(self.p, "c/x"), "DETECTED")
    def test_last_verdict_none_when_absent(self):
        self.assertIsNone(last_verdict(self.p, "c/none"))


class TestLedgerRow(unittest.TestCase):
    """`validation/lib/attack-report.js` renders `row.error` on an ABORT and prints
    "with no error recorded" when it is absent. Nothing wrote that field until
    2026-09-04, so the fake-CAPTCHA delivery failure repeated on three separate
    nights with the cause visible only in a /tmp log."""

    def _r(self, executed, status, verdict):
        return Result(id="t/x", rule_ids=["r1"], executor="rdp_keystroke",
                      executed=executed, status=status, verdict=verdict,
                      attack_start="2026-09-04T04:00:00+00:00",
                      attack_end="2026-09-04T04:00:10+00:00")

    def test_an_abort_carries_the_executor_status_as_error(self):
        row = _ledger_row(self._r(False, "BAD_KEYSTROKE: multi-line command", Verdict.ABORT), "ts")
        self.assertEqual(row["error"], "BAD_KEYSTROKE: multi-line command")

    def test_a_run_that_executed_carries_no_error_key(self):
        row = _ledger_row(self._r(True, "SUCCESS", Verdict.DETECTED), "ts")
        self.assertNotIn("error", row)

    def test_the_row_shape_is_otherwise_unchanged(self):
        row = _ledger_row(self._r(True, "SUCCESS", Verdict.DETECTED), "ts")
        self.assertEqual(set(row), {"id", "rule_ids", "run_ts", "host", "verdict",
                                    "latency_s", "attack_start", "attack_end", "co_firing",
                                    "rule_versions", "rule_query_hashes"})

if __name__ == "__main__":
    unittest.main()
