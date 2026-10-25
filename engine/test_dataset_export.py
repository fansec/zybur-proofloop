# rules/engine/pending_test_dataset_export.py
# Slice 5: the record and the catalogue as a dataset a researcher can cite, with host names mapped to
# roles, a publication lag, and the scoreboard aggregates. RED by design until the slice lands.
import importlib
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))

HOSTS = {"hosts": [
    {"name": "production", "role": "workstation", "aliases": ["infected"], "ip": "10.0.0.2", "host_id": "h1"},
    {"name": "dc1", "role": "domain_controller", "aliases": ["DC1", "DC1.example.lab"], "ip": "10.0.0.3", "host_id": "h2"},
]}

def row(uid, day, verdict, host="production", latency=None, rule="r1"):
    return {"id": uid, "verdict": verdict, "attack_start": f"2026-09-{day:02d}T04:00:00+00:00",
            "attack_end": f"2026-09-{day:02d}T04:00:05+00:00", "run_ts": f"2026-09-{day:02d}T04:00:06+00:00",
            "latency_s": latency, "rule_ids": [rule], "co_firing": ["Other Rule"], "rule_versions": {rule: 2},
            "rule_query_hashes": {rule: "abc"}, "rechecked_at": None,
            "host": {"name": host, "id": "h1" if host == "production" else "h2", "aliases": ["infected"]},
            "output": "stdout the row should never carry", "nonce": "deadbeef"}

LEDGER = [
    row("a/one", 1, "DETECTED", latency=100.0),
    row("a/one", 5, "MISSED"),
    row("a/one", 9, "DETECTED", latency=200.0),
    row("b/two", 2, "PREVENTED", host="dc1"),
    row("b/two", 3, "PENDING", host="dc1"),
    row("b/two", 3, "DETECTED", host="dc1", latency=50.0),
    row("c/never", 20, "DETECTED", latency=10.0),   # inside the lag window: must be cut
    row("z/unknown-host", 4, "DETECTED", host="mystery", latency=5.0),
]

USECASES = [
    {"id": "a/one", "title": "One", "technique": "T1059", "tactic": "execution", "severity": "LOW", "safety": "safe",
     "evidence": "real_behaviour", "expect": "detected", "executor": "winrm_command", "rules": ["Rule One"], "rule_ids": ["r1"]},
    {"id": "b/two", "title": "Two", "technique": "T1003", "tactic": "credential-access", "severity": "HIGH", "safety": "supervised",
     "evidence": "stand_in", "expect": "detected", "executor": "ad_directory", "rules": ["Rule Two"], "rule_ids": ["r2"]},
    {"id": "c/never", "title": "Never", "technique": "T1486", "tactic": "impact", "severity": "HIGH", "safety": "never",
     "evidence": "real_behaviour", "expect": "detected", "executor": "winrm_command", "rules": ["Rule Three"], "rule_ids": ["r3"]},
    {"id": "canary/zybur-proofloop-canary", "title": "Canary", "technique": "T1059", "tactic": "execution", "severity": "LOW", "safety": "safe",
     "evidence": "real_behaviour", "expect": "detected", "executor": "winrm_command", "rules": ["Canary Rule"], "rule_ids": ["r9"]},
]

FORBIDDEN_RECORD_KEYS = {"host", "output", "nonce", "aliases", "host_id"}


class TestBuild(unittest.TestCase):
    def build(self, **kw):
        mod = importlib.import_module("dataset_export")
        args = dict(usecases=USECASES, ledger_rows=LEDGER, hosts=HOSTS, until="2026-09-30", lag_days=15)
        args.update(kw)
        return mod.build(**args)

    def test_catalogue_leaves_out_never_and_canary(self):
        cat = self.build()["catalogue"]
        self.assertEqual([c["id"] for c in cat], ["a/one", "b/two"])
        self.assertEqual(set(cat[0]), {"id", "title", "technique", "tactic", "severity", "safety", "evidence",
                                       "expect", "executor", "rules", "rule_ids"})

    def test_record_maps_hosts_to_roles_and_drops_raw_fields(self):
        rec = self.build()["record"]
        self.assertTrue(rec)
        for r in rec:
            self.assertEqual(FORBIDDEN_RECORD_KEYS & set(r), set(), r)
            self.assertIn(r["host_role"], ("workstation", "domain_controller", "unknown"))
        roles = {(r["id"], r["host_role"]) for r in rec}
        self.assertIn(("a/one", "workstation"), roles)
        self.assertIn(("b/two", "domain_controller"), roles)
        self.assertIn(("z/unknown-host", "unknown"), roles)
        self.assertNotIn("mystery", json.dumps(rec))

    def test_lag_cuts_rows_newer_than_until_minus_lag(self):
        rec = self.build()["record"]
        self.assertNotIn("c/never", {r["id"] for r in rec}, "a row 10 days old is inside the 15-day lag")
        self.assertEqual(max(r["attack_start"] for r in rec)[:10], "2026-09-09")

    def test_scoreboard_aggregates_finals_only(self):
        sb = self.build()["scoreboard"]
        self.assertEqual(sb["until"], "2026-09-30")
        self.assertEqual(sb["lag_days"], 15)
        one = sb["use_cases"]["a/one"]
        self.assertEqual((one["detected"], one["missed"], one["prevented"], one["nights"]), (2, 1, 0, 3))
        self.assertEqual(one["latest_final"], "DETECTED")
        self.assertEqual(one["latest_final_at"][:10], "2026-09-09")
        self.assertEqual(one["median_latency_s"], 150.0)
        two = sb["use_cases"]["b/two"]
        self.assertEqual((two["detected"], two["prevented"], two["nights"]), (1, 1, 2), "PENDING is not a night")
        self.assertNotIn("canary/zybur-proofloop-canary", sb["use_cases"])
        self.assertEqual(sb["totals"]["use_cases"], 2)


class TestCli(unittest.TestCase):
    def test_cli_writes_the_four_files_and_a_citation(self):
        tmp = tempfile.mkdtemp()
        with open(os.path.join(tmp, "ledger.jsonl"), "w") as f:
            for r in LEDGER:
                f.write(json.dumps(r) + "\n")
        with open(os.path.join(tmp, "hosts.json"), "w") as f:
            json.dump(HOSTS, f)
        ucdir = os.path.join(tmp, "usecases", "a"); os.makedirs(ucdir)
        with open(os.path.join(ucdir, "one.yaml"), "w") as f:
            f.write('id: a/one\ntitle: "One"\ntechnique: T1059\ntactic: execution\nseverity: LOW\nsafety: safe\n'
                    'evidence: real_behaviour\nexpect: detected\nexecutor: winrm_command\nrules:\n- "Rule One"\n'
                    'params:\n  platform: windows\n  shell: psh\n  command: "echo hi"\n')
        out = os.path.join(tmp, "dataset")
        p = subprocess.run([sys.executable, os.path.join(HERE, "dataset_export.py"), "--out", out,
                            "--ledger", os.path.join(tmp, "ledger.jsonl"), "--hosts", os.path.join(tmp, "hosts.json"),
                            "--usecases", os.path.join(tmp, "usecases"), "--until", "2026-09-30", "--lag-days", "15",
                            "--no-lock"], capture_output=True, text=True, cwd=HERE)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        for f in ("catalogue.json", "catalogue.csv", "record.jsonl", "scoreboard.json", "schema.md", "CITATION.cff"):
            self.assertTrue(os.path.exists(os.path.join(out, f)), f)
        self.assertRegex(p.stdout, r"^dataset: use-cases=1 rows=\d+ until=2026-09-30 lag_days=15$")
        text = pathlib.Path(out, "record.jsonl").read_text()
        for bad in ("production", "infected", "mystery", "deadbeef", "stdout the row"):
            self.assertNotIn(bad, text, bad)


if __name__ == "__main__":
    unittest.main()
