# rules/engine/pending_test_report_md.py
# Slice 3: the attack report rendered by the engine itself (markdown), so a public user gets the
# "Detected, prevented or missed" table and the per-attack explanation without the Node loop.
# RED by design until the slice lands; rename to test_report_md.py when green.
import importlib
import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))

RESULTS = [
    {"id": "t/detected", "rule_ids": ["r1"], "executor": "winrm_command", "executed": True, "status": "SUCCESS",
     "verdict": "DETECTED", "attack_start": "2026-10-01T04:00:00+00:00", "attack_end": "2026-10-01T04:00:05+00:00",
     "latency_s": 115.2, "output": "", "op_id": "", "expect": "detected",
     "host": {"name": "ws", "id": "h1", "aliases": []}, "co_firing": ["Another Rule"], "rule_versions": {"r1": 3},
     "rule_query_hashes": {}, "nonce": None},
    {"id": "t/missed", "rule_ids": ["r2"], "executor": "caldera_command", "executed": True, "status": "SUCCESS",
     "verdict": "MISSED", "attack_start": "2026-10-01T04:10:00+00:00", "attack_end": "2026-10-01T04:10:05+00:00",
     "latency_s": None, "output": "", "op_id": "", "expect": "detected",
     "host": {"name": "ws", "id": "h1", "aliases": []}, "co_firing": [], "rule_versions": {},
     "rule_query_hashes": {}, "nonce": None},
    {"id": "t/prevented", "rule_ids": ["r3"], "executor": "winrm_command", "executed": True, "status": "SUCCESS",
     "verdict": "PREVENTED", "attack_start": "2026-10-01T04:20:00+00:00", "attack_end": "2026-10-01T04:20:05+00:00",
     "latency_s": None, "output": "", "op_id": "", "expect": "detected",
     "host": {"name": "dc", "id": "h2", "aliases": []}, "co_firing": [], "rule_versions": {},
     "rule_query_hashes": {}, "nonce": None},
]

USECASES = {
    "t/detected": {"id": "t/detected", "title": "Detected Thing", "technique": "T1059", "tactic": "execution",
                   "executor": "winrm_command", "description": "Runs a harmless marker.", "rules": ["Rule One"]},
    "t/missed": {"id": "t/missed", "title": "Missed Thing", "technique": "T1127.001", "tactic": "defense-evasion",
                 "executor": "caldera_command", "description": "Starts a build engine.", "rules": ["Rule Two"]},
    "t/prevented": {"id": "t/prevented", "title": "Prevented Thing", "technique": "T1003", "tactic": "credential-access",
                    "executor": "winrm_command", "description": "Touches lsass.", "rules": ["Rule Three"]},
}


class TestRender(unittest.TestCase):
    def render(self):
        mod = importlib.import_module("report_md")
        return mod.render_attack_report(RESULTS, USECASES, night="2026-10-01")

    def test_front_matter_counts_every_verdict(self):
        md = self.render()
        self.assertTrue(md.startswith("---\n"), md[:40])
        self.assertIn("night: 2026-10-01", md)
        self.assertIn("attack_execution: DETECTED 1, MISSED 1, PREVENTED 1 over 3 use-cases on dc, ws", md)

    def test_table_has_one_row_per_result_with_the_measured_fields(self):
        md = self.render()
        self.assertIn("## Detected, prevented or missed", md)
        self.assertIn("| Use-case | Technique | Verdict | Latency (s) | Target rule fired | Also fired in the window |", md)
        self.assertIn("| `t/detected` | T1059 | DETECTED | 115.2 | yes | Another Rule |", md)
        self.assertIn("| `t/missed` | T1127.001 | MISSED | n/a | no | nothing else fired |", md)
        self.assertIn("| `t/prevented` | T1003 | PREVENTED | n/a | no | nothing else fired |", md)

    def test_each_attack_is_explained_from_its_use_case(self):
        md = self.render()
        self.assertIn("## How each attack was executed", md)
        self.assertIn("### t/missed - MISSED", md)
        self.assertIn("- Missed Thing (T1127.001, defense-evasion)", md)
        self.assertIn("- what it does: Starts a build engine.", md)
        self.assertIn("- window: 2026-10-01T04:10:00+00:00 to 2026-10-01T04:10:05+00:00 (5.0s on the box)", md)
        self.assertIn("- delivered by: caldera_command", md)
        self.assertIn("- target rule: Rule Two", md)

    def test_an_absent_field_renders_as_absent_never_as_zero(self):
        r = dict(RESULTS[1]); r["latency_s"] = None; r["co_firing"] = None
        mod = importlib.import_module("report_md")
        md = mod.render_attack_report([r], USECASES, night="2026-10-01")
        self.assertIn("| n/a |", md)
        self.assertNotIn("| 0 |", md)

    def test_no_use_case_file_is_still_rendered(self):
        mod = importlib.import_module("report_md")
        md = mod.render_attack_report([RESULTS[0]], {}, night="2026-10-01")
        self.assertIn("### t/detected - DETECTED", md)
        self.assertIn("- use-case file not found", md)


class TestCli(unittest.TestCase):
    def test_cli_renders_a_results_file_to_stdout(self):
        tmp = tempfile.mkdtemp()
        p = os.path.join(tmp, "results.json")
        with open(p, "w") as f:
            json.dump(RESULTS, f)
        ucdir = os.path.join(tmp, "usecases", "t")
        os.makedirs(ucdir)
        for uid, uc in USECASES.items():
            with open(os.path.join(ucdir, uid.split("/")[1] + ".yaml"), "w") as f:
                f.write("id: %s\ntitle: \"%s\"\ntechnique: %s\ntactic: %s\nexecutor: %s\ndescription: \"%s\"\nrules:\n- \"%s\"\n"
                        "safety: safe\nexpect: detected\nseverity: LOW\nparams:\n  platform: windows\n  shell: psh\n  command: \"echo hi\"\n"
                        % (uid, uc["title"], uc["technique"], uc["tactic"], uc["executor"], uc["description"], uc["rules"][0]))
        out = subprocess.run([sys.executable, os.path.join(HERE, "report_md.py"), p, "--usecases", os.path.join(tmp, "usecases"),
                              "--night", "2026-10-01"], capture_output=True, text=True, cwd=HERE)
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertIn("## Detected, prevented or missed", out.stdout)
        self.assertIn("### t/prevented - PREVENTED", out.stdout)


if __name__ == "__main__":
    unittest.main()
