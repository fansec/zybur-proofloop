# rules/engine/test_record_night.py
"""--record-night is read-only and what it writes replays to the ledger's verdicts."""
import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timezone, timedelta
from unittest import mock

import run as runmod
import testenv

T0 = datetime(2026, 10, 1, 4, 0, 0, tzinfo=timezone.utc)
HOST = {"name": "ws-test", "id": "00000000-0000-4000-8000-0000000000aa", "aliases": []}
RID = "11111111-2222-4333-8444-555555555555"


def load(path):
    with open(path) as f:
        return json.load(f)


def load_text(path):
    with open(path) as f:
        return f.read()


def dump(doc, path):
    with open(path, "w") as f:
        json.dump(doc, f)


def replay_quietly(d):
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        return runmod.replay(d)


def setUpModule():
    testenv.use_fixture_lab_hosts_for_module()
    testenv.use_sample_pack_for_module()


class StubElastic:
    name = "elastic"
    es_url = "https://es.example.invalid"
    api_key = "k"

    def __init__(self, alerts):
        self.alerts, self.calls = alerts, []

    def query_alerts(self, rule_ids, since_iso, hosts=None):
        self.calls.append((list(rule_ids), since_iso, hosts))
        return self.alerts


def result(uid, rid, minute):
    return {"id": uid, "rule_ids": [rid], "executor": "winrm_command", "executed": True,
            "status": "SUCCESS", "verdict": "PENDING",
            "attack_start": (T0 + timedelta(minutes=minute)).isoformat(),
            "attack_end": (T0 + timedelta(minutes=minute, seconds=5)).isoformat(),
            "latency_s": None, "output": "secret lab output", "op_id": "op", "expect": "detected",
            "host": dict(HOST), "co_firing": [], "rule_versions": {}, "rule_query_hashes": {},
            "nonce": "n1"}


class TestRecordNight(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.results = os.path.join(self.tmp, "results")
        os.makedirs(self.results)
        rs = [result("t/hit", RID, 0), result("t/miss", "r-other", 10)]
        dump(rs, os.path.join(self.results, "usecases_20261001T040001Z.json"))
        self.ledger = os.path.join(self.tmp, "ledger.jsonl")
        rows = []
        for r, verdict in zip(rs, ("DETECTED", "MISSED")):
            rows.append({**{k: r[k] for k in ("id", "rule_ids", "attack_start", "attack_end", "host")},
                         "verdict": "PENDING", "run_ts": r["attack_start"]})
            rows.append({**rows[-1], "verdict": verdict,
                         "rechecked_at": (T0 + timedelta(minutes=30)).isoformat()})
        with open(self.ledger, "w") as f:
            f.write("".join(json.dumps(x) + "\n" for x in rows))
        self.alert = {"rule_id": RID, "name": "Some Rule", "host_name": "ws-test", "host_id": HOST["id"],
                      "@timestamp": (T0 + timedelta(minutes=2)).isoformat(), "original_time": None,
                      "event_ingested": None, "winlog_computer_name": None, "event_type": ["start"],
                      "event_dataset": None, "group_id": None, "group_index": None,
                      "building_block_type": None, "rule_version": 1}
        late = {**self.alert, "@timestamp": (T0 + timedelta(days=1)).isoformat()}
        self.stub = StubElastic([self.alert, late])

    def record(self):
        out = os.path.join(self.tmp, "out")
        with mock.patch.object(runmod, "LEDGER", self.ledger), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            rc = runmod.record_night("2026-10-01", out, adapter=self.stub, results_dir=self.results)
        return rc, out

    def test_records_one_search_per_host_and_replays_to_the_ledger(self):
        before = load_text(self.ledger)
        rc, out = self.record()
        self.assertEqual(rc, 0)
        self.assertEqual(len(self.stub.calls), 1, "one search per host")
        self.assertEqual(load_text(self.ledger), before, "recording never writes the ledger")
        d = os.path.join(out, "ws-test")
        self.assertEqual(sorted(os.listdir(d)), ["alerts.json", "expected.json", "inputs.json"])
        self.assertEqual(load(os.path.join(d, "expected.json")),
                         {"t/hit": "DETECTED", "t/miss": "MISSED"})
        self.assertEqual(len(load(os.path.join(d, "alerts.json"))), 1,
                         "an alert newer than the recorded clock is not part of the night")
        self.assertEqual(replay_quietly(d), 0)

    def test_lab_text_never_reaches_the_fixture(self):
        _, out = self.record()
        text = load_text(os.path.join(out, "ws-test", "inputs.json"))
        for leak in ("secret lab output", '"op"', '"n1"'):
            self.assertNotIn(leak, text)

    def test_without_a_live_siem_it_refuses(self):
        self.stub.api_key = None
        rc, _ = self.record()
        self.assertEqual(rc, 2)


class TestReplayNeedsNothing(unittest.TestCase):
    def test_no_rule_export_no_lab_registry_no_ledger_no_credentials(self):
        """A stranger's checkout has none of these; the replay must not reach for them."""
        env = {k: v for k, v in os.environ.items()
               if not k.startswith(("ES_", "ELASTIC_", "SIEM"))}
        env.update(RULES_EXPORT="/nonexistent/export.ndjson", LAB_HOSTS_FILE="/nonexistent/lab.json",
                   LEDGER_FILE="/nonexistent/ledger.jsonl", ZYBUR_ENV_ROOT=tempfile.mkdtemp(),
                   ZYBUR_CREDS_FILE=os.devnull, ES_URL="https://127.0.0.1:1", ES_API_KEY="unused")
        here = os.path.dirname(os.path.abspath(__file__))
        p = subprocess.run([sys.executable, os.path.join(here, "run.py"), "--replay",
                            os.path.join(here, "fixtures", "replay", "sample-night")],
                           env=env, capture_output=True, text=True, cwd=here)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertRegex(p.stdout, r"replay: (\d+) of \1 verdicts match expected\.json")


class TestAdapterSelection(unittest.TestCase):
    def test_elastic_without_a_url_or_a_key_answers_none_and_makes_no_request(self):
        import siem.elastic
        http = mock.Mock(side_effect=AssertionError("no request without a url and a key"))
        http.Request = http.urlopen = http
        for url, key in ((None, "k"), ("https://x", None), (None, None), ("", "k")):
            with self.subTest(url=url, key=bool(key)):
                self.assertIsNone(siem.elastic.ElasticAdapter(url, key, http=http).query_alerts(["r"], "2026-01-01T00:00:00Z"))
    def test_recorded_needs_its_directory_and_an_unknown_name_is_refused(self):
        import siem
        with self.assertRaises(ValueError) as cm:
            siem.adapter_from_env({"SIEM": "recorded"})
        self.assertIn("SIEM_RECORDED_DIR", str(cm.exception))
        self.assertEqual(siem.adapter_from_env({"SIEM": "Recorded", "SIEM_RECORDED_DIR": "/x"}).name, "recorded")
        with self.assertRaises(ValueError) as cm:
            siem.adapter_from_env({"SIEM": "splunk"})
        self.assertIn("unknown SIEM adapter", str(cm.exception))

    def test_credential_precedence_is_the_old_one(self):
        import siem
        shared = {"ELASTIC_VALIDATION_API_KEY": "v", "ELASTIC_LEGACY_API_KEY": "l",
                  "ELASTIC_VALIDATION_URL": "https://v", "ELASTIC_URL": "https://u"}
        read = shared.get
        self.assertEqual(siem.elastic_credentials({"ES_URL": "https://e", "ES_API_KEY": "k"}, read=read),
                         ("https://e", "k"))
        self.assertEqual(siem.elastic_credentials({}, read=read), ("https://v", "v"))
        del shared["ELASTIC_VALIDATION_API_KEY"], shared["ELASTIC_VALIDATION_URL"]
        self.assertEqual(siem.elastic_credentials({}, read=read), ("https://u", "l"))
        self.assertEqual(siem.elastic_credentials({}, read={}.get), (None, None))

    def test_no_credentials_still_means_alerts_none_and_inconclusive(self):
        res = runmod.Result(**{**result("t/x", RID, 0), "verdict": None, "output": "", "op_id": "",
                               "nonce": None})
        with mock.patch.object(runmod, "_es_credentials", return_value=(None, None)), \
                mock.patch.object(runmod.verifymod, "query_alerts") as q, \
                mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("SIEM", None)
            runmod.verify_results([res], {RID: "5m"}, now=T0 + timedelta(hours=2), host=HOST,
                                  extra_starts=[], extra_ends=[], extra_detonations=[])
        q.assert_not_called()
        self.assertEqual(res.verdict, runmod.Verdict.INCONCLUSIVE)

    def test_siem_env_selects_the_recorded_adapter_without_credentials(self):
        d = tempfile.mkdtemp()
        dump([], os.path.join(d, "alerts.json"))
        res = runmod.Result(**{**result("t/x", RID, 0), "verdict": None, "output": "", "op_id": "",
                               "nonce": None})
        with mock.patch.object(runmod, "_es_credentials", side_effect=AssertionError("not consulted")), \
                mock.patch.dict(os.environ, {"SIEM": "recorded", "SIEM_RECORDED_DIR": d}):
            runmod.verify_results([res], {RID: "5m"}, now=T0 + timedelta(hours=2), host=HOST,
                                  extra_starts=[], extra_ends=[], extra_detonations=[])
        self.assertEqual(res.verdict, runmod.Verdict.MISSED)


class TestReplayIsHonest(unittest.TestCase):
    def test_a_fixture_cannot_carry_its_own_verdict(self):
        d = tempfile.mkdtemp()
        res = result("t/miss", "r-other", 0)
        res.update(verdict="DETECTED", latency_s=1.0)
        res["host"] = {"name": "ws", "id": "h1", "aliases": []}
        inputs = {"schema_version": 1, "night": "2026-10-01", "now": (T0 + timedelta(hours=1)).isoformat(),
                  "host": res["host"], "rule_intervals": {"r-other": "5m"}, "results": [res],
                  "extra_starts": [], "extra_ends": [], "extra_detonations": []}
        for name, doc in (("inputs.json", inputs), ("alerts.json", []), ("expected.json", {"t/miss": "MISSED"})):
            dump(doc, os.path.join(d, name))
        self.assertEqual(replay_quietly(d), 0)

    def test_unknown_schema_version_is_refused(self):
        d = tempfile.mkdtemp()
        for name, doc in (("inputs.json", {"schema_version": 99}), ("expected.json", {})):
            dump(doc, os.path.join(d, name))
        self.assertEqual(replay_quietly(d), 2)

    def test_an_empty_or_malformed_fixture_is_exit_2_never_a_pass(self):
        """0 of 0 is not a pass, and a traceback is not 'a verdict differed' (exit 1)."""
        base = {"schema_version": 1, "night": "2026-10-01", "now": T0.isoformat(),
                "host": {"name": "ws", "id": "h1", "aliases": []}, "rule_intervals": {},
                "results": [], "extra_starts": [], "extra_ends": [], "extra_detonations": []}
        row = {**result("t/x", RID, 0), "host": base["host"]}
        cases = {
            "no results": (base, {}),
            "no expectations": ({**base, "results": [row]}, {}),
            "unknown result key": ({**base, "results": [{**row, "zzz": 1}]}, {"t/x": "MISSED"}),
            "no now": ({k: v for k, v in {**base, "results": [row]}.items() if k != "now"}, {"t/x": "MISSED"}),
            "no results key": ({k: v for k, v in base.items() if k != "results"}, {"t/x": "MISSED"}),
        }
        good = {**base, "results": [row]}
        exp = {"t/x": "MISSED"}
        for field, value in (("rule_intervals", None), ("host", "ws"), ("extra_detonations", ["x"]),
                             ("extra_starts", ["junk"]), ("now", "junk")):
            cases[f"{field}={value!r}"] = ({**good, field: value}, exp)
        cases["attack_start junk"] = ({**good, "results": [{**row, "attack_start": "junk"}]}, exp)
        cases["rule_ids null"] = ({**good, "results": [{**row, "rule_ids": None}]}, exp)
        cases["inputs not an object"] = ([], exp)
        for label, (inputs, expected) in cases.items():
            with self.subTest(label):
                d = tempfile.mkdtemp()
                for name, doc in (("inputs.json", inputs), ("alerts.json", []), ("expected.json", expected)):
                    dump(doc, os.path.join(d, name))
                self.assertEqual(replay_quietly(d), 2)
        # Alerts the classifier cannot read are a malformed fixture too, not a failed verdict.
        alert = {"rule_id": RID, "name": "Some Rule", "host_name": "ws", "host_id": "h1",
                 "@timestamp": (T0 + timedelta(minutes=2)).isoformat(), "original_time": None,
                 "event_ingested": None, "winlog_computer_name": None, "event_type": ["start"],
                 "event_dataset": None, "group_id": None, "group_index": None,
                 "building_block_type": None, "rule_version": 1}
        for label, alerts in {"string alert": ["x"], "alert without a timestamp": [{k: v for k, v in alert.items() if k != "@timestamp"}]}.items():
            with self.subTest(label):
                d = tempfile.mkdtemp()
                for name, doc in (("inputs.json", good), ("alerts.json", alerts), ("expected.json", exp)):
                    dump(doc, os.path.join(d, name))
                self.assertEqual(replay_quietly(d), 2)


if __name__ == "__main__":
    unittest.main()
