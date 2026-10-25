# rules/engine/test_run_recheck.py
"""--recheck-pending has to be MACHINE-readable, because a machine now drives it.

Validation's SETTLE stage polls this until nothing is PENDING and then rewrites
its VERIFY gate from the per-id verdicts. Before 2026-07-28 the only output was a
counts line for a human reading cron logs, and nothing called it at all: every
nightly verdict sat at PENDING forever because the loop verifies seconds after
detonation, before any rule has next run.
"""
import io
import json
import unittest
from contextlib import redirect_stdout

from datetime import datetime, timezone, timedelta

import run as runmod
import testenv
from run import (_recheck_ledger_row, _recheck_report, _query_hashes_for, missed_rows_within,
                 RECHECK_MISSED_MAX_DAYS)
from result import Result, Verdict
from rulehash import rule_query_hash


def setUpModule():
    testenv.use_fixture_lab_hosts_for_module()
    testenv.use_sample_pack_for_module()


class Row:
    def __init__(self, uid, verdict, latency=None):
        self.id, self.verdict, self.latency_s = uid, verdict, latency


def emit(results, as_json=True):
    buf = io.StringIO()
    with redirect_stdout(buf):
        _recheck_report(results, as_json)
    return buf.getvalue().strip()


class TestRecheckReport(unittest.TestCase):
    def test_json_carries_every_id_and_its_verdict(self):
        # Counts alone cannot say WHICH use-case resolved to what, and the gate
        # records one check per id. This is the whole reason for the flag.
        doc = json.loads(emit([Row("c/a", Verdict.DETECTED, 145.9),
                               Row("c/b", Verdict.PREVENTED),
                               Row("c/c", Verdict.PENDING)]))
        self.assertEqual(doc["rechecked"], 3)
        self.assertEqual(doc["pending"], 1)
        self.assertEqual([r["id"] for r in doc["results"]], ["c/a", "c/b", "c/c"])
        self.assertEqual(doc["results"][0]["verdict"], "DETECTED")
        self.assertAlmostEqual(doc["results"][0]["latency_s"], 145.9)
        self.assertIsNone(doc["results"][1]["latency_s"])

    def test_an_empty_pass_is_the_same_shape(self):
        # An empty pass is the SUCCESS condition for the settle poll: "nothing is
        # pending any more". A poll that had to tell `{}` from a parse failure
        # would treat a broken engine as a finished night.
        # `written` joined the shape on 2026-08-05 with --recheck-missed, which
        # writes only the verdicts that CHANGED: "re-checked 8, wrote 0" and
        # "re-checked 0" are different nights and the ops line has to tell them
        # apart. Asserted exactly, still, because the settle poll stops on this.
        doc = json.loads(emit([]))
        self.assertEqual(doc, {"rechecked": 0, "pending": 0, "written": 0, "results": []})

    def test_pending_is_zero_when_every_row_resolved(self):
        doc = json.loads(emit([Row("c/a", Verdict.DETECTED), Row("c/b", Verdict.MISSED)]))
        self.assertEqual(doc["pending"], 0, "the poll stops on this, so it must be exact")

    def test_a_verdictless_row_is_NONE_and_still_not_pending(self):
        doc = json.loads(emit([Row("c/a", None)]))
        self.assertIsNone(doc["results"][0]["verdict"])
        self.assertEqual(doc["pending"], 0)

    def test_the_human_line_is_unchanged_without_the_flag(self):
        # cron output is still read by a person; --json is additive, not a swap.
        self.assertEqual(emit([Row("c/a", Verdict.DETECTED)], as_json=False),
                         "rechecked 1 PENDING row(s): {'DETECTED': 1}")


NOW = datetime(2026, 8, 5, 6, 0, tzinfo=timezone.utc)


def mrow(uid, days_ago, verdict="MISSED", **kw):
    d = {"id": uid, "verdict": verdict,
         "attack_start": (NOW - timedelta(days=days_ago)).isoformat()}
    d.update(kw)
    return d


class TestMissedRowsWithin(unittest.TestCase):
    """--recheck-missed's age bound, which is the whole reason it is safe to run.

    MISSED used to be terminal: nothing re-read it, so an alert arriving after the
    20-minute SETTLE poll could never correct the record. Measured 2026-08-05
    against live Elastic, EIGHT of the 19 MISSED rows still inside retention had
    their own target rule's alert sitting in the due window - seven of them purely
    because the alert had not been INGESTED yet when the loop stopped looking. The
    worst arrived 7h16m late.

    Re-checking is only honest while Elastic can still answer. Past retention the
    absence of a document is retention, not evidence.
    """

    def test_rows_inside_the_window_are_returned(self):
        rows = [mrow("a", 1), mrow("b", 6)]
        self.assertEqual([r["id"] for r in missed_rows_within(rows, NOW, 7)], ["a", "b"])

    def test_rows_older_than_the_window_are_dropped(self):
        rows = [mrow("a", 1), mrow("old", 30)]
        self.assertEqual([r["id"] for r in missed_rows_within(rows, NOW, 7)], ["a"])

    def test_a_row_with_no_attack_start_is_dropped(self):
        # An age that cannot be established must not read as young. Confirming a
        # MISSED against an index that may have aged out is the one way this
        # command can manufacture a detection failure.
        rows = [mrow("nostart", 1)]
        rows[0].pop("attack_start")
        self.assertEqual(missed_rows_within(rows, NOW, 7), [])

    def test_only_the_latest_verdict_per_id_counts(self):
        # A row already corrected to DETECTED by an earlier re-check is finished.
        rows = [mrow("fixed", 3), mrow("fixed", 3, "DETECTED", rechecked_at="x"), mrow("b", 3)]
        self.assertEqual([r["id"] for r in missed_rows_within(rows, NOW, 7)], ["b"])

    def test_the_max_is_below_live_elastic_retention(self):
        # Live retention measured 31d (inherited Serverless cap). The ceiling has to
        # stay under it with room to spare, or the guard above is decoration.
        self.assertLess(RECHECK_MISSED_MAX_DAYS, 31)


class TestRecheckBoundsFromTheLedger(unittest.TestCase):
    """A re-check ends a row's window at the NEXT detonation's floor, read from the ledger.

    Since 2026-10-14 a window stops at next start - CLOCK_SKEW_S (verify.
    attribution_until), not at next start. A re-check builds its results from ledger
    rows, so the successor is only visible through the ledger's starts; these pin
    that the re-check paths get the same bound as the nightly. The pair is the live
    2026-10-11 mshta / psengine one: psengine's block at behavior 04:04:30.571Z sat
    inside mshta's old window too.
    """

    D = datetime(2026, 10, 11, 4, 4, 0, tzinfo=timezone.utc)
    MSHTA = {"id": "defense-evasion/sample-a",
             "rule_ids": ["181f6b23-3799-445e-9589-0018328a9e46"], "executor": "e"}
    PSENGINE = {"id": "execution/sample-b",
                "rule_ids": ["852c1f19-68e8-43a6-9dce-340771fe1be3"], "executor": "e"}
    RULES = {"181f6b23-3799-445e-9589-0018328a9e46": "5m",
             "852c1f19-68e8-43a6-9dce-340771fe1be3": "5m"}

    def _at(self, s, ms=0):
        return (self.D + timedelta(seconds=s, milliseconds=ms)).isoformat()

    def _row(self, uc, verdict, start, end):
        return {"id": uc["id"], "rule_ids": uc["rule_ids"], "run_ts": end,
                "host": {"name": "production", "id": None}, "verdict": verdict,
                "latency_s": None, "attack_start": start, "attack_end": end,
                "co_firing": []}

    def _block(self):
        return {"rule_id": "9a1a2dae-0b5f-4c3d-8305-a268d404c306",
                "name": "Malicious Behavior Prevention Alert: Execution via Renamed "
                        "Signed Binary Proxy",
                "host_name": "production", "host_id": None,
                "event_type": ["info", "denied"],
                "original_time": self._at(30, 571), "@timestamp": self._at(72, 740)}

    def _recheck(self, fn, ledger_rows, alerts):
        import os, tempfile
        import run as runmod
        import ledger as ledgermod
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = os.path.join(tmp.name, "ledger.jsonl")
        ledgermod.append(path, ledger_rows)
        saved = (runmod.LEDGER, runmod.verifymod.query_alerts, runmod._es_credentials,
                 runmod.load_config)
        runmod.LEDGER = path
        runmod.verifymod.query_alerts = lambda *a, **kw: alerts
        runmod._es_credentials = lambda: ("https://es.example", "key")
        # Every row carries a host, so the config is never consulted; stubbed so
        # the test never reads the credential file load_config resolves from.
        runmod.load_config = lambda: {}
        try:
            buf = io.StringIO()
            with redirect_stdout(buf):
                fn([self.MSHTA, self.PSENGINE], self.RULES,
                   now=self.D + timedelta(minutes=16), as_json=True)
            return json.loads(buf.getvalue().strip().splitlines()[0]), ledgermod.read(path)
        finally:
            (runmod.LEDGER, runmod.verifymod.query_alerts, runmod._es_credentials,
             runmod.load_config) = saved

    def test_recheck_pending_does_not_credit_the_next_rows_block(self):
        from run import recheck_pending
        rows = [self._row(self.MSHTA, "PENDING", self._at(20, 199), self._at(20, 562)),
                self._row(self.PSENGINE, "PREVENTED", self._at(30, 613), self._at(34, 318))]
        doc, after = self._recheck(recheck_pending, rows, [self._block()])
        self.assertEqual([(r["id"], r["verdict"]) for r in doc["results"]],
                         [(self.MSHTA["id"], "MISSED")],
                         "the psengine block made this re-check PREVENTED before 2026-10-14")
        self.assertEqual(after[-1]["co_firing"], [])

    def test_recheck_missed_writes_nothing_for_the_next_rows_block(self):
        # The re-check that could have WRITTEN the false PREVENTED: a standing
        # MISSED flipped by its neighbour's block. It must stay MISSED and the
        # ledger must keep its size.
        from run import recheck_missed
        rows = [self._row(self.MSHTA, "MISSED", self._at(20, 199), self._at(20, 562)),
                self._row(self.PSENGINE, "PREVENTED", self._at(30, 613), self._at(34, 318))]
        doc, after = self._recheck(recheck_missed, rows, [self._block()])
        self.assertEqual(doc["written"], 0)
        self.assertEqual(doc["results"][0]["verdict"], "MISSED")
        self.assertEqual(len(after), 2)


    def test_a_key_without_a_url_refuses_and_leaves_the_ledger_alone(self):
        # A half-configured verifier used to append INCONCLUSIVE over the real
        # MISSED row and exit 0 (the URL was a default until 2026-10-22).
        import os, tempfile
        import run as runmod
        import ledger as ledgermod
        from run import recheck_missed
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = os.path.join(tmp.name, "ledger.jsonl")
        ledgermod.append(path, [self._row(self.MSHTA, "MISSED", self._at(20, 199), self._at(20, 562))])
        saved = (runmod.LEDGER, runmod._es_credentials, runmod.load_config)
        runmod.LEDGER = path
        runmod._es_credentials = lambda: (None, "key")
        runmod.load_config = lambda: {}
        try:
            out, err = io.StringIO(), io.StringIO()
            from contextlib import redirect_stderr
            with redirect_stdout(out), redirect_stderr(err):
                code = recheck_missed([self.MSHTA], self.RULES,
                                      now=self.D + timedelta(minutes=16), as_json=True)
            rows = ledgermod.read(path)
        finally:
            runmod.LEDGER, runmod._es_credentials, runmod.load_config = saved
        self.assertEqual(code, 2)
        self.assertIn("ES_URL", err.getvalue())
        self.assertEqual([r["verdict"] for r in rows], ["MISSED"])


class TestRecheckLedgerRow(unittest.TestCase):
    def test_row_carries_rule_versions(self):
        # D1: without it every DETECTED recheck row read as an unmeasured proof version.
        class R:
            id, rule_ids, host = "c/a", ["r1"], "WS1"
            verdict, latency_s = Verdict.DETECTED, 12.0
            attack_start, attack_end, co_firing = "s", "e", []
            rule_versions = {"r1": 216}
            rule_query_hashes = {"r1": "0123456789abcdef"}
        now = datetime(2026, 10, 20, tzinfo=timezone.utc)
        row = _recheck_ledger_row(R, {"run_ts": "t0"}, now)
        self.assertEqual(row["rule_versions"], {"r1": 216})
        self.assertEqual(row["rule_query_hashes"], {"r1": "0123456789abcdef"})
        self.assertEqual(row["run_ts"], "t0")
        self.assertEqual(row["rechecked_at"], now.isoformat())


class TestQueryHashesFor(unittest.TestCase):
    def _pack_rule(self):
        # The hash is computed from whatever export the engine is pointed at, and the
        # module points it at the sample pack (the public export has no live one).
        with open(runmod.EXPORT, encoding="utf-8") as f:
            for line in f:
                d = json.loads(line) if line.strip() else {}
                if d.get("rule_id") and d.get("enabled") and d.get("name"):
                    return d
        raise AssertionError("no enabled rule in the export")

    def test_an_export_rule_gets_the_hash_of_its_export_line(self):
        d = self._pack_rule()
        self.assertEqual(_query_hashes_for({d["rule_id"]: d["version"]}),
                         {d["rule_id"]: rule_query_hash(d)})

    def test_each_export_rule_gets_its_own_hash(self):
        # The sample rules carry different queries, so a swapped rule-to-hash mapping,
        # or a hash that ignored the query, would show here and not as two equal values.
        rules = []
        with open(runmod.EXPORT, encoding="utf-8") as f:
            for line in f:
                d = json.loads(line) if line.strip() else {}
                if d.get("rule_id") and d.get("enabled") and d.get("name"):
                    rules.append(d)
        self.assertGreaterEqual(len(rules), 2)
        got = _query_hashes_for({d["rule_id"]: d["version"] for d in rules})
        self.assertEqual(got, {d["rule_id"]: rule_query_hash(d) for d in rules})
        self.assertEqual(len(set(got.values())), len(rules), "two rules hashed alike")

    def test_a_managed_rule_gets_no_key_not_a_null(self):
        # zybur-proofloop-canary is in rule_versions of a proof but never in the export.
        d = self._pack_rule()
        got = _query_hashes_for({d["rule_id"]: 1, "zybur-proofloop-canary": 1, "not-a-rule": 3})
        self.assertEqual(set(got), {d["rule_id"]})

    def test_nothing_proven_is_an_empty_map(self):
        self.assertEqual(_query_hashes_for({}), {})

    def test_both_ledger_row_builders_write_the_same_map(self):
        from run import _ledger_row
        d = self._pack_rule()
        r = Result(id="c/a", rule_ids=[d["rule_id"]], executor="x", executed=True, status="SUCCESS",
                   verdict=Verdict.DETECTED, attack_start="s", attack_end="e",
                   rule_versions={d["rule_id"]: d["version"]})
        r.rule_query_hashes = _query_hashes_for(r.rule_versions)
        now = datetime(2026, 10, 20, tzinfo=timezone.utc)
        self.assertEqual(_ledger_row(r, "t")["rule_query_hashes"],
                         _recheck_ledger_row(r, {"run_ts": "t"}, now)["rule_query_hashes"])
        self.assertEqual(_ledger_row(r, "t")["rule_query_hashes"], {d["rule_id"]: rule_query_hash(d)})


if __name__ == "__main__":
    unittest.main()
