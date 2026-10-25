# rules/engine/test_dataset_export_edges.py
# Edge cases of dataset_export that the slice 5 acceptance suite does not pin: the inclusive lag
# boundary, rows the lag cannot be applied to, dict co_firing entries, CSV quoting, empty input.
import contextlib
import csv
import io
import json
import os
import tempfile
import unittest

import dataset_export as de

HOSTS = [{"name": "box", "role": "workstation", "aliases": ["old"], "host_id": "id-1"}]
UC = [{"id": "a/one", "title": 'A "quoted", title', "technique": "T1", "tactic": "execution", "severity": "LOW",
       "safety": "safe", "rules": ["R1", "R2"], "rule_ids": ["x", "y"]}]


def row(start, verdict="DETECTED", host=None, **kw):
    r = {"id": "a/one", "verdict": verdict, "attack_start": start, "host": host if host is not None else {"name": "box"},
         "co_firing": [{"name": "R", "rule_id": "x", "prevented": False, "ts": "t", "secret": "no"}]}
    r.update(kw)
    return r


def build(rows, **kw):
    args = dict(usecases=UC, ledger_rows=rows, hosts=HOSTS, until="2026-09-30", lag_days=10, today="2026-10-01")
    args.update(kw)
    return de.build(**args)


class TestEdges(unittest.TestCase):
    def test_boundary_day_is_inclusive_and_offsets_use_the_written_date(self):
        rec = build([row("2026-09-20T23:59:59+00:00"), row("2026-09-21T00:00:00Z"), row("2026-09-20T01:00:00+02:00")])["record"]
        self.assertEqual([r["attack_start"][:10] for r in rec], ["2026-09-20", "2026-09-20"])

    def test_rows_without_date_or_verdict_are_left_out(self):
        rec = build([row(None), row("2026-09-01T00:00:00Z", verdict=None), row("2026-09-01T00:00:00Z")])["record"]
        self.assertEqual(len(rec), 1)

    def test_co_firing_dicts_keep_only_published_keys(self):
        rec = build([row("2026-09-01T00:00:00Z")])["record"]
        self.assertEqual(set(rec[0]["co_firing"][0]), {"name", "rule_id", "prevented", "ts"})

    def test_host_lookup_by_alias_and_by_id_when_unnamed_and_missing_host_is_unknown(self):
        rows = [row("2026-09-01T00:00:00Z", host={"name": "OLD"}), row("2026-09-02T00:00:00Z", host={"id": "id-1"}),
                row("2026-09-03T00:00:00Z", host=False), row("2026-09-04T00:00:00Z", host={"name": "other", "id": "id-1"})]
        rows[2]["host"] = None
        self.assertEqual([r["host_role"] for r in build(rows)["record"]], ["workstation", "workstation", "unknown", "unknown"])

    def test_empty_ledger_and_use_case_without_nights(self):
        out = build([])
        self.assertEqual(out["record"], [])
        one = out["scoreboard"]["use_cases"]["a/one"]
        self.assertEqual((one["nights"], one["latest_final"], one["median_latency_s"], one["proof_age_days"]), (0, None, None, None))

    def test_proof_age_and_missing_latency(self):
        sb = build([row("2026-09-10T00:00:00Z", latency_s=None), row("2026-09-12T00:00:00Z", verdict="MISSED")])["scoreboard"]
        one = sb["use_cases"]["a/one"]
        self.assertEqual((one["proof_age_days"], one["median_latency_s"], one["latest_final"]), (20, None, "MISSED"))

    def test_csv_quotes_commas_and_joins_lists(self):
        rows = list(csv.reader(io.StringIO(de._catalogue_csv(build([])["catalogue"]))))
        self.assertEqual(rows[1][1], 'A "quoted", title')
        self.assertEqual(rows[1][rows[0].index("rules")], "R1; R2")

    def test_bad_arguments_raise(self):
        with self.assertRaises(ValueError):
            build([], until="30-09-2026")
        with self.assertRaises(ValueError):
            build([], lag_days=-1)

    def test_drafts_stay_out_of_catalogue_record_and_scoreboard(self):
        ucs = UC + [{"id": "a/draft", "title": "D", "safety": "supervised", "status": "draft"}]
        rows = [row("2026-09-01T00:00:00Z"), row("2026-09-01T00:00:00Z", id="a/draft")]
        out = build(rows, usecases=ucs)
        self.assertEqual([c["id"] for c in out["catalogue"]], ["a/one"])
        self.assertEqual([r["id"] for r in out["record"]], ["a/one"])
        self.assertNotIn("a/draft", out["scoreboard"]["use_cases"])


class TestCliRefusals(unittest.TestCase):
    """A typo must not turn into a published dataset: each refusal is exit 2 and writes nothing."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        t = self.tmp.name
        self.ledger = os.path.join(t, "ledger.jsonl")
        with open(self.ledger, "w") as f:
            f.write(json.dumps(row("2026-09-01T00:00:00Z")) + "\n")
        self.hosts = os.path.join(t, "hosts.json")
        with open(self.hosts, "w") as f:
            json.dump({"hosts": HOSTS}, f)
        self.ucdir = os.path.join(t, "uc")
        os.makedirs(self.ucdir)
        with open(os.path.join(self.ucdir, "one.yaml"), "w") as f:
            f.write("id: a/one\ntitle: One\nsafety: safe\n")
        self.out = os.path.join(t, "out")

    def run_cli(self, **over):
        a = dict(ledger=self.ledger, hosts=self.hosts, usecases=self.ucdir)
        a.update(over)
        argv = ["--out", self.out, "--ledger", a["ledger"], "--hosts", a["hosts"], "--usecases", a["usecases"],
                "--until", "2026-12-31", "--lag-days", "0", "--no-lock"]
        with contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()):
            return de.main(argv)

    def test_good_input_writes(self):
        self.assertEqual(self.run_cli(), 0)
        self.assertTrue(os.path.exists(os.path.join(self.out, "record.jsonl")))

    def test_missing_ledger_is_refused(self):
        self.assertEqual(self.run_cli(ledger=os.path.join(self.tmp.name, "nope.jsonl")), 2)
        self.assertFalse(os.path.exists(self.out))

    def test_missing_or_empty_usecase_folder_is_refused(self):
        self.assertEqual(self.run_cli(usecases=os.path.join(self.tmp.name, "nope")), 2)
        empty = os.path.join(self.tmp.name, "empty")
        os.makedirs(empty)
        self.assertEqual(self.run_cli(usecases=empty), 2)
        self.assertFalse(os.path.exists(self.out))

    def test_unparseable_usecase_file_is_refused(self):
        with open(os.path.join(self.ucdir, "broken.yaml"), "w") as f:
            f.write("id: a/two\nsafety: [never\n")
        self.assertEqual(self.run_cli(), 2)
        self.assertFalse(os.path.exists(self.out))

    def test_invalid_safety_or_status_value_is_refused(self):
        # `Never` and `nevr` are not `never`: the filter would publish the use-case and its rows.
        for body in ("safety: Never\n", "safety: nevr\n", "", "safety: safe\nstatus: Draft\n"):
            with self.subTest(body=body):
                with open(os.path.join(self.ucdir, "typo.yaml"), "w") as f:
                    f.write("id: a/two\ntitle: Two\n" + body)
                self.assertEqual(self.run_cli(), 2)
                self.assertFalse(os.path.exists(self.out))


if __name__ == "__main__":
    unittest.main()
