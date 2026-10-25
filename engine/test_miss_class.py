# rules/engine/pending_test_miss_class.py
# Slice 6 (engine half): a MISSED is classified against the ledger before the loop decides whether it is an
# alarm, and flapping use-cases are counted. RED by design until the slice lands.
import unittest
from datetime import datetime, timezone, timedelta

import selector as sel
from result import Result

NOW = datetime(2026, 10, 22, 4, 30, tzinfo=timezone.utc)

def row(uid, days_ago, verdict):
    ts = (NOW - timedelta(days=days_ago)).isoformat()
    return {"id": uid, "run_ts": ts, "attack_start": ts, "verdict": verdict}


class TestMissClass(unittest.TestCase):
    def test_not_a_miss_is_none(self):
        self.assertIsNone(sel.miss_class([row("u", 3, "DETECTED")], "DETECTED"))
        self.assertIsNone(sel.miss_class([row("u", 3, "DETECTED")], "PENDING"))

    def test_first_miss_after_a_good_final(self):
        rows = [row("u", 9, "DETECTED"), row("u", 2, "PREVENTED"), row("u", 1, "PENDING")]
        self.assertEqual(sel.miss_class(rows, "MISSED"), "first_miss")

    def test_confirmed_regression_is_the_second_consecutive_miss_after_a_good_final(self):
        rows = [row("u", 9, "DETECTED"), row("u", 2, "MISSED")]
        self.assertEqual(sel.miss_class(rows, "MISSED"), "confirmed_regression")
        rows = [row("u", 9, "DETECTED"), row("u", 3, "MISSED"), row("u", 2, "MISSED")]
        self.assertEqual(sel.miss_class(rows, "MISSED"), "confirmed_regression")

    def test_never_detected_when_no_good_final_exists(self):
        self.assertEqual(sel.miss_class([], "MISSED"), "never_detected")
        self.assertEqual(sel.miss_class([row("u", 3, "MISSED"), row("u", 1, "INCONCLUSIVE")], "MISSED"), "never_detected")

    def test_pending_and_inconclusive_rows_do_not_count_as_finals(self):
        rows = [row("u", 9, "DETECTED"), row("u", 2, "PENDING"), row("u", 1, "INCONCLUSIVE")]
        self.assertEqual(sel.miss_class(rows, "MISSED"), "first_miss")

    def test_order_is_by_run_ts_not_by_list_position(self):
        rows = [row("u", 2, "MISSED"), row("u", 9, "DETECTED")]
        self.assertEqual(sel.miss_class(rows, "MISSED"), "confirmed_regression")


class TestFlapping(unittest.TestCase):
    def test_flapping_lists_use_cases_with_both_outcomes_in_the_window(self):
        rows = [row("flap", 20, "DETECTED"), row("flap", 10, "MISSED"), row("flap", 3, "DETECTED"),
                row("steady", 20, "DETECTED"), row("steady", 3, "DETECTED"),
                row("broken", 20, "MISSED"), row("broken", 3, "MISSED"),
                row("old-flap", 40, "MISSED"), row("old-flap", 35, "DETECTED"), row("old-flap", 3, "DETECTED")]
        self.assertEqual(sel.flapping(rows, NOW, days=30), ["flap"])

    def test_select_nightly_meta_carries_flapping(self):
        ucs = [{"id": "flap", "severity": "LOW", "safety": "safe", "expect": "detected"},
               {"id": "steady", "severity": "LOW", "safety": "safe", "expect": "detected"}]
        rows = [row("flap", 20, "DETECTED"), row("flap", 10, "MISSED"), row("flap", 3, "DETECTED"),
                row("steady", 20, "DETECTED"), row("steady", 3, "DETECTED")]
        _ids, meta = sel.select_nightly(ucs, rows, 2, now=NOW)
        self.assertEqual(meta["flapping"], 1)
        self.assertEqual(meta["flapping_ids"], ["flap"])


class TestResultCarriesTheClass(unittest.TestCase):
    def test_result_has_a_miss_class_field_that_reaches_to_dict(self):
        r = Result(id="u", rule_ids=["r1"], executor="e", executed=True, status="SUCCESS")
        self.assertIsNone(r.miss_class)
        r.miss_class = "first_miss"
        self.assertEqual(r.to_dict()["miss_class"], "first_miss")


if __name__ == "__main__":
    unittest.main()
