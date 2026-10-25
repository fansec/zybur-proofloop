# rules/engine/test_miss_class_ledger.py
"""Slice 6 (2026-10-22): a MISSED is classified against the ledger from BEFORE this detonation.

pending_test_miss_class (now test_miss_class.py) pins miss_class() and flapping() as pure
functions. These pin what the pure tests cannot: that every path which writes a verdict hands
the function the right history. Tonight's own row, or the row being re-checked, in that history
turns a first miss into a second one and the night goes red over a single failure; an unreadable
ledger passed on as an empty one turns every MISSED into "never detected", which the loop treats
as a pass.
"""
import contextlib
import io
import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

import ledger as ledgermod
import run as runmod
import selector as sel
import testenv
from result import Result, Verdict, make_result

T0 = datetime(2026, 10, 10, 4, 0, tzinfo=timezone.utc)
UC = {"id": "exec/alpha", "rule_ids": ["rule-1"], "executor": "e", "target": "workstation"}
RULES = {"rule-1": "5m"}


def setUpModule():
    testenv.use_fixture_lab_hosts_for_module()
    testenv.use_sample_pack_for_module()


def at(days):
    return (T0 + timedelta(days=days)).isoformat()


def lrow(days, verdict, **kw):
    ts = at(days)
    d = {"id": UC["id"], "rule_ids": UC["rule_ids"], "run_ts": ts, "attack_start": ts, "attack_end": ts,
         "host": {"name": "ws", "id": "h1"}, "verdict": verdict, "co_firing": []}
    d.update(kw)
    return d


class Ledger:
    """A throwaway ledger file, patched in as run.LEDGER for the length of a with block."""

    def __init__(self, test, rows=None, raw=None):
        self.tmp = tempfile.TemporaryDirectory()
        test.addCleanup(self.tmp.cleanup)
        self.path = os.path.join(self.tmp.name, "ledger.jsonl")
        if rows is not None:
            ledgermod.append(self.path, rows)
        if raw is not None:
            with open(self.path, "w") as f:
                f.write(raw)

    def rows(self):
        return ledgermod.read(self.path)


class TestDetonationPath(unittest.TestCase):
    """main() with a verifier that says MISSED: the class on the written row and in --emit-json."""

    def detonate(self, ledger_path, verdict=Verdict.MISSED):
        emit = os.path.join(os.path.dirname(ledger_path), "emit.json")

        def fake_verify(results, rule_intervals, now=None):
            for r in results:
                r.verdict = verdict

        def handler(u, ctx):
            return make_result(u, "SUCCESS", True, attack_start=at(30), attack_end=at(30))

        err = io.StringIO()
        with testenv.no_lab_values(ZYBUR_ENV_ROOT=os.path.dirname(ledger_path),
                                   LAB_HOSTS_FILE=testenv.LAB_HOSTS_FIXTURE), \
                mock.patch.object(runmod, "LEDGER", ledger_path), \
                mock.patch.object(runmod, "load_enabled_rules", return_value={}), \
                mock.patch.object(runmod, "load_usecases", return_value=[UC]), \
                mock.patch.object(runmod, "load_config", return_value={}), \
                mock.patch.object(runmod, "config_for_target", side_effect=lambda c, t: {}), \
                mock.patch.object(runmod, "target_host", return_value={"name": "ws", "id": "h1"}), \
                mock.patch.object(runmod, "missing_for_target", return_value=[]), \
                mock.patch.object(runmod, "CalderaClient"), \
                mock.patch.object(runmod, "DedupAllocator", return_value=mock.Mock(spec=["assert_pool_safe", "cleanup"])), \
                mock.patch.object(runmod, "FirewallService"), \
                mock.patch.object(runmod, "_wait_for_detonation_gap"), \
                mock.patch.object(runmod, "_warn_if_detonations_too_close"), \
                mock.patch.object(runmod, "_es_credentials", return_value=("https://es.example", "k")), \
                mock.patch.object(runmod, "_verify_by_host", side_effect=fake_verify), \
                mock.patch.object(runmod, "_write_results", return_value="results.json"), \
                mock.patch.object(runmod.registry, "get", return_value=handler), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
            rc = runmod.main(["--id", UC["id"], "--verify", "--emit-json", emit])
        with open(emit) as f:
            emitted = json.load(f)
        return rc, emitted[0], err.getvalue()

    def test_first_miss_after_a_good_final_and_tonights_row_is_not_in_the_history(self):
        led = Ledger(self, [lrow(1, "DETECTED")])
        rc, emitted, _err = self.detonate(led.path)
        self.assertEqual(rc, 0)
        self.assertEqual(emitted["miss_class"], "first_miss")
        written = led.rows()[-1]
        self.assertEqual((written["verdict"], written["miss_class"]), ("MISSED", "first_miss"))

    def test_the_second_consecutive_miss_is_a_confirmed_regression(self):
        led = Ledger(self, [lrow(1, "DETECTED"), lrow(2, "MISSED")])
        _rc, emitted, _err = self.detonate(led.path)
        self.assertEqual(emitted["miss_class"], "confirmed_regression")

    def test_an_empty_ledger_that_exists_is_a_history_of_nothing(self):
        led = Ledger(self, raw="")
        _rc, emitted, _err = self.detonate(led.path)
        self.assertEqual(emitted["miss_class"], "never_detected")

    def test_a_missing_ledger_file_leaves_the_class_unset_and_says_why(self):
        led = Ledger(self)
        _rc, emitted, err = self.detonate(led.path)
        self.assertIsNone(emitted["miss_class"], "an unavailable ledger must not read as an empty one")
        self.assertIn("the ledger cannot be read", err)
        self.assertIn("stays red", err)

    def test_a_truncated_ledger_leaves_the_class_unset_and_says_why(self):
        led = Ledger(self, raw=json.dumps(lrow(1, "DETECTED")) + '\n{"id": "exec/alpha", "run_ts": "2026-10')
        _rc, emitted, err = self.detonate(led.path)
        self.assertIsNone(emitted["miss_class"])
        self.assertIn("the ledger cannot be read", err)

    def test_a_final_row_with_no_run_ts_leaves_the_class_unset(self):
        # A miss that cannot be placed in time must not be skipped: skipping it can read a
        # confirmed regression as a first miss.
        bad = lrow(2, "MISSED")
        del bad["run_ts"]
        led = Ledger(self, [lrow(1, "DETECTED"), bad])
        _rc, emitted, err = self.detonate(led.path)
        self.assertIsNone(emitted["miss_class"])
        self.assertIn("miss_class not set for exec/alpha", err)

    def test_a_verdict_that_is_not_a_miss_carries_no_class_and_no_key_in_the_row(self):
        led = Ledger(self, [lrow(1, "DETECTED")])
        _rc, emitted, _err = self.detonate(led.path, verdict=Verdict.DETECTED)
        self.assertIsNone(emitted["miss_class"])
        self.assertNotIn("miss_class", led.rows()[-1])


class TestRecheckPaths(unittest.TestCase):
    """--recheck-pending and --recheck-missed: the row under re-check is not its own history."""

    def recheck(self, fn, rows):
        led = Ledger(self, rows)
        with mock.patch.object(runmod, "LEDGER", led.path), \
                mock.patch.object(runmod.verifymod, "query_alerts", lambda *a, **kw: []), \
                mock.patch.object(runmod, "_es_credentials", return_value=("https://es.example", "k")), \
                mock.patch.object(runmod, "load_config", return_value={}), \
                mock.patch.object(runmod, "_apply_memory_check"):
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                fn([UC], RULES, now=T0 + timedelta(days=33), as_json=True)
        return json.loads(out.getvalue().strip().splitlines()[0]), led.rows()

    def test_recheck_pending_settling_to_missed_is_a_first_miss_after_a_good_final(self):
        doc, after = self.recheck(runmod.recheck_pending, [lrow(1, "DETECTED"), lrow(30, "PENDING")])
        self.assertEqual(doc["results"][0]["verdict"], "MISSED")
        self.assertEqual(doc["results"][0]["miss_class"], "first_miss",
                         "the PENDING row of this very detonation is on file and must not count")
        self.assertEqual(after[-1]["miss_class"], "first_miss")
        self.assertEqual(after[-1]["run_ts"], at(30), "a re-check keeps the ORIGINAL run_ts")

    def test_recheck_pending_after_an_earlier_miss_is_a_confirmed_regression(self):
        doc, _after = self.recheck(runmod.recheck_pending,
                                   [lrow(1, "DETECTED"), lrow(2, "MISSED"), lrow(30, "PENDING")])
        self.assertEqual(doc["results"][0]["miss_class"], "confirmed_regression")

    def test_recheck_pending_of_a_use_case_that_never_detected(self):
        doc, _after = self.recheck(runmod.recheck_pending, [lrow(2, "MISSED"), lrow(30, "PENDING")])
        self.assertEqual(doc["results"][0]["miss_class"], "never_detected")

    def test_recheck_missed_does_not_count_the_row_it_is_re_checking(self):
        # The standing MISSED stays MISSED, so nothing is written, but the report still says what
        # kind it is. With its own row in the history it would read as a confirmed regression.
        doc, after = self.recheck(runmod.recheck_missed, [lrow(1, "DETECTED"), lrow(30, "MISSED")])
        self.assertEqual(doc["results"][0]["miss_class"], "first_miss")
        self.assertEqual(doc["written"], 0)
        self.assertEqual(len(after), 2)

    def test_recheck_missed_with_an_earlier_miss_is_a_confirmed_regression(self):
        doc, _after = self.recheck(runmod.recheck_missed,
                                   [lrow(1, "DETECTED"), lrow(20, "MISSED"), lrow(30, "MISSED")])
        self.assertEqual(doc["results"][0]["miss_class"], "confirmed_regression")

    def test_a_later_detonation_written_earlier_in_the_file_is_not_history(self):
        # Rows are cut off by run_ts, not by file position: the row under re-check is the last
        # one in the file (day 30), the day-31 detonation sits before it.
        doc, _after = self.recheck(runmod.recheck_missed,
                                   [lrow(1, "DETECTED"), lrow(31, "MISSED"), lrow(30, "MISSED")])
        self.assertEqual(doc["results"][0]["miss_class"], "first_miss")

    def test_a_row_that_settles_to_a_hit_carries_no_class(self):
        r = Result(id="a", rule_ids=[], executor="e", executed=True, status="RECHECK", verdict=Verdict.DETECTED)
        with mock.patch.object(runmod, "LEDGER", Ledger(self, [lrow(1, "DETECTED")]).path):
            runmod._apply_miss_classes([r], [lrow(30, "PENDING")])
        self.assertIsNone(r.miss_class)

    def test_an_original_without_a_run_ts_leaves_the_class_unset(self):
        r = Result(id=UC["id"], rule_ids=[], executor="e", executed=True, status="RECHECK", verdict=Verdict.MISSED)
        orig = lrow(30, "PENDING")
        del orig["run_ts"]
        err = io.StringIO()
        with mock.patch.object(runmod, "LEDGER", Ledger(self, [lrow(1, "DETECTED")]).path), \
                contextlib.redirect_stderr(err):
            runmod._apply_miss_classes([r], [orig])
        self.assertIsNone(r.miss_class)
        self.assertIn("miss_class not set", err.getvalue())


class TestPlacement(unittest.TestCase):
    def test_a_final_row_that_cannot_be_placed_raises_instead_of_being_skipped(self):
        rows = [lrow(1, "DETECTED"), {"id": "a", "verdict": "MISSED"}]
        with self.assertRaises(ValueError):
            sel.miss_class(rows, "MISSED")

    def test_rows_that_are_not_finals_need_no_timestamp(self):
        rows = [lrow(1, "DETECTED"), {"id": "a", "verdict": "PENDING"}, {"id": "a", "verdict": None}]
        self.assertEqual(sel.miss_class(rows, "MISSED"), "first_miss")

    def test_mixed_utc_spellings_order_by_instant(self):
        rows = [{"id": "a", "run_ts": "2026-10-02T00:00:00Z", "verdict": "MISSED"},
                {"id": "a", "run_ts": "2026-10-01T00:00:00+00:00", "verdict": "DETECTED"},
                {"id": "a", "run_ts": "2026-10-03T00:00:00", "verdict": "MISSED"}]
        self.assertEqual(sel.miss_class(rows, "MISSED"), "confirmed_regression")

    def test_a_miss_corrected_by_a_later_recheck_is_one_detonation_with_its_last_final(self):
        # --recheck-missed writes the correction under the ORIGINAL run_ts. [MISSED, DETECTED] for
        # one run_ts is a detonation that detected, not a use-case that flipped.
        rows = [lrow(1, "DETECTED"), lrow(5, "MISSED"), lrow(5, "DETECTED", rechecked_at=at(6))]
        self.assertEqual(sel.miss_class(rows, "MISSED"), "first_miss")
        self.assertEqual(sel.flapping([lrow(5, "MISSED"), lrow(5, "DETECTED", rechecked_at=at(6))],
                                      T0 + timedelta(days=10)), [])


class TestFlappingEdges(unittest.TestCase):
    NOW = datetime(2026, 10, 22, 4, 30, tzinfo=timezone.utc)

    def r(self, uid, ts, verdict):
        return {"id": uid, "run_ts": ts, "verdict": verdict}

    def test_the_window_is_inclusive_at_exactly_thirty_days(self):
        edge = (self.NOW - timedelta(days=30)).isoformat()
        just_out = (self.NOW - timedelta(days=30, seconds=1)).isoformat()
        inside = (self.NOW - timedelta(days=1)).isoformat()
        self.assertEqual(sel.flapping([self.r("a", edge, "MISSED"), self.r("a", inside, "DETECTED")], self.NOW), ["a"])
        self.assertEqual(sel.flapping([self.r("a", just_out, "MISSED"), self.r("a", inside, "DETECTED")], self.NOW), [])

    def test_a_row_dated_after_now_is_outside_the_window(self):
        later = (self.NOW + timedelta(hours=1)).isoformat()
        self.assertEqual(sel.flapping([self.r("a", later, "MISSED"),
                                       self.r("a", (self.NOW - timedelta(days=1)).isoformat(), "DETECTED")], self.NOW), [])

    def test_naive_and_z_timestamps_are_read_as_utc(self):
        rows = [self.r("a", "2026-10-20T04:30:00", "MISSED"), self.r("a", "2026-10-21T04:30:00Z", "PREVENTED")]
        self.assertEqual(sel.flapping(rows, self.NOW), ["a"])
        self.assertEqual(sel.flapping(rows, self.NOW.replace(tzinfo=None)), ["a"])

    def test_null_verdicts_and_rows_without_a_timestamp_count_for_nothing_and_do_not_raise(self):
        rows = [self.r("a", (self.NOW - timedelta(days=2)).isoformat(), None),
                {"id": "a", "verdict": "MISSED"},
                self.r("a", (self.NOW - timedelta(days=1)).isoformat(), "DETECTED"),
                {"verdict": "MISSED", "run_ts": self.NOW.isoformat()}]
        self.assertEqual(sel.flapping(rows, self.NOW), [])

    def test_pending_and_inconclusive_do_not_make_a_flap(self):
        rows = [self.r("a", (self.NOW - timedelta(days=3)).isoformat(), "INCONCLUSIVE"),
                self.r("a", (self.NOW - timedelta(days=2)).isoformat(), "DETECTED")]
        self.assertEqual(sel.flapping(rows, self.NOW), [])

    def test_the_stderr_summary_names_the_count(self):
        ucs = [dict(id="a", severity="LOW", safety="safe", expect="detected")]
        rows = [self.r("a", (self.NOW - timedelta(days=3)).isoformat(), "MISSED"),
                self.r("a", (self.NOW - timedelta(days=2)).isoformat(), "DETECTED")]
        err, out = io.StringIO(), io.StringIO()
        with testenv.no_lab_values(ZYBUR_ENV_ROOT=tempfile.gettempdir(), LAB_HOSTS_FILE=testenv.LAB_HOSTS_FIXTURE), \
                mock.patch.object(runmod, "load_enabled_rules", return_value={}), \
                mock.patch.object(runmod, "load_usecases", return_value=ucs), \
                mock.patch.object(runmod, "load_config", return_value={}), \
                mock.patch.object(runmod.ledgermod, "read", return_value=rows), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            runmod.main(["--select-nightly", "5"])
        self.assertIn("flapping=1", err.getvalue())


if __name__ == "__main__":
    unittest.main()
