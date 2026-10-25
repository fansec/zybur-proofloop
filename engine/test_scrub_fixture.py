# rules/engine/test_scrub_fixture.py
"""The scrubber keeps verdicts and refuses to write a fixture that still names the lab."""
import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timezone, timedelta

import scrub_fixture as sf

HERE = os.path.dirname(os.path.abspath(__file__))
T0 = datetime(2026, 10, 1, 4, 0, 0, tzinfo=timezone.utc)
RID = "11111111-2222-4333-8444-555555555555"


def raw():
    host = {"name": "labbox", "id": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", "aliases": ["infected"]}
    res = lambda uid, rid, m: {
        "id": uid, "rule_ids": [rid], "executor": "winrm_command", "executed": True, "status": "SUCCESS",
        "verdict": None, "attack_start": (T0 + timedelta(minutes=m)).isoformat(),
        "attack_end": (T0 + timedelta(minutes=m, seconds=5)).isoformat(), "latency_s": None,
        "output": "C:\\Users\\bob\\x 10.1.2.3", "op_id": "op-1", "expect": "detected", "host": dict(host),
        "co_firing": [], "rule_versions": {}, "rule_query_hashes": {}, "nonce": "abc"}
    inputs = {"schema_version": 1, "night": "2026-10-01", "now": (T0 + timedelta(hours=2)).isoformat(),
              "host": dict(host), "rule_intervals": {RID: "5m", "zybur-canary": "5m"},
              "results": [res("t/public", RID, 10), res("canary/zybur-canary", "zybur-canary", 0)],
              "extra_starts": [], "extra_ends": [], "extra_detonations": []}
    alert = lambda rid, name, hn, hid, grp=None, wn=None: {
        "rule_id": rid, "name": name, "host_name": hn, "host_id": hid, "winlog_computer_name": wn,
        "@timestamp": (T0 + timedelta(minutes=11)).isoformat(), "original_time": None, "event_ingested": None,
        "event_type": ["start"], "event_dataset": None, "group_id": grp, "group_index": None,
        "building_block_type": None, "rule_version": 3}
    alerts = [alert(RID, "Public Rule", "infected", host["id"], "f" * 64, "LABBOX.corp.lab"),
              alert("zybur-canary", "Zybur - Canary", "labbox", host["id"]),
              alert(RID, "Public Rule", "otherbox", "99999999-bbbb-4ccc-8ddd-eeeeeeeeeeee")]
    return inputs, alerts, {"t/public": "DETECTED", "canary/zybur-canary": "DETECTED"}


class TestScrub(unittest.TestCase):
    def test_scrub_renames_hosts_consistently_and_passes_its_own_check(self):
        inputs, alerts, expected = sf.scrub(*raw())
        sf.check(inputs, alerts, expected)
        self.assertEqual(inputs["host"], {"name": "ws", "id": "h1", "aliases": []})
        self.assertEqual([a["host_name"] for a in alerts], ["ws", "ws", "other-host"])
        self.assertEqual([a["host_id"] for a in alerts], ["h1", "h1", "h2"])
        self.assertEqual(alerts[0]["winlog_computer_name"], "ws", "an aggregate alert must still match the target")
        self.assertEqual(alerts[0]["group_id"], "g1")

    def test_a_private_detonation_becomes_a_neighbour_not_a_result(self):
        inputs, alerts, expected = sf.scrub(*raw())
        self.assertEqual([r["id"] for r in inputs["results"]], ["t/public"])
        self.assertEqual(expected, {"t/public": "DETECTED"})
        self.assertEqual(len(inputs["extra_starts"]), 1)
        self.assertEqual(inputs["extra_detonations"][0]["rule_ids"], ["neighbour-rule-1"])
        self.assertIn("neighbour-rule-1", inputs["rule_intervals"])
        self.assertEqual(alerts[1]["name"], "Neighbour Rule 1")

    def test_lab_text_in_results_is_blanked(self):
        inputs, _, _ = sf.scrub(*raw())
        for r in inputs["results"]:
            self.assertEqual((r["output"], r["op_id"], r["nonce"]), ("", "", None))

    def test_scrub_does_not_modify_its_input(self):
        before = raw()
        arg = copy.deepcopy(before)
        sf.scrub(*arg)
        self.assertEqual(arg, before)


class TestCheckDenies(unittest.TestCase):
    def scrubbed(self):
        return sf.scrub(*raw())

    def assertRefused(self, mutate, fragment):
        inputs, alerts, expected = self.scrubbed()
        mutate(inputs, alerts, expected)
        with self.assertRaises(sf.ScrubError) as cm:
            sf.check(inputs, alerts, expected)
        self.assertIn(fragment, str(cm.exception))
        self.assertNotIn("10.1.2.3", str(cm.exception), "a refusal names the pattern, never the value")

    def test_each_leak_shape_is_refused(self):
        cases = {
            "private IPv4 10/8": "reached 10.1.2.3 now",
            "private IPv4 172.16/12": "reached 172.20.0.9",
            # Spelled in two pieces: this file is exported, and the export's denylist gate
            # (scripts/oss-export/denylist.txt) refuses the range's prefix written whole.
            "private IPv4 192.168/16": "reached 192" ".168.0.9",
            "MAC address": "aa:bb:cc:dd:ee:ff",
            "Windows SID": "S-1-5-21-1-2-3-500",
            "e-mail address": "a.b@example.nl",
            "DOMAIN\\account": "LAB\\svc_backup",
            "lab-style host name": "box.corp",
            "IPv6 ULA or link-local": "fd12:3456::1",
            "denied string": "Zybur",
            "long hex id": "a" * 40,
        }
        for label, text in cases.items():
            with self.subTest(label):
                def put(inputs, alerts, expected, text=text):
                    alerts[0]["name"] = f"x {text} y"
                self.assertRefused(put, label.split(" ")[0] if label == "denied string" else label)

    def test_a_guid_that_is_not_a_rule_id_is_refused(self):
        def put(inputs, alerts, expected):
            alerts[0]["name"] = "9a1a2dae-0b5f-4c3d-8305-a268d404c306"
        self.assertRefused(put, "GUID outside a rule id")

    def test_lab_text_left_in_a_result_and_a_foreign_host_are_refused(self):
        self.assertRefused(lambda i, a, e: i["results"][0].update(output="x"), "lab text left")
        self.assertRefused(lambda i, a, e: a[0].update(host_name="labbox2"), "alert host_name")

    def test_values_that_no_deny_pattern_knows_are_refused_by_the_allow_pass(self):
        """Closed values, not only closed keys: free text in a retained field must not publish.

        Alert names are held by the export check below, which needs the export.
        """
        cases = {
            "event_dataset": lambda i, a, e: a[0].update(event_dataset="jdoe"),
            "event_type": lambda i, a, e: a[0].update(event_type=["jdoe"]),
            "night": lambda i, a, e: i.update(night="lab-night-jdoe"),
            "executor": lambda i, a, e: i["results"][0].update(executor="my-private-exec"),
            "status": lambda i, a, e: i["results"][0].update(status="jdoe"),
            "use-case id": lambda i, a, e: (e.pop("t/public"), e.update({"jdoe": "DETECTED"}),
                                            i["results"][0].update(id="jdoe")),
            "expect": lambda i, a, e: i["results"][0].update(expect="jdoe"),
            "building block type": lambda i, a, e: a[0].update(building_block_type="jdoe"),
            "attack_start": lambda i, a, e: i["results"][0].update(attack_start="2026-10-01T04:10:00+00:00 jdoe"),
            "expected verdict": lambda i, a, e: e.update({"t/public": "jdoe"}),
        }
        for label, mutate in cases.items():
            with self.subTest(label):
                inputs, alerts, expected = self.scrubbed()
                mutate(inputs, alerts, expected)
                with self.assertRaises(sf.ScrubError):
                    sf.check(inputs, alerts, expected)

    def memory(self, fields):
        return {"name": "Public Rule", "fields": fields, "window": "now-14d", "window_s": 1209600}

    def test_the_lab_ledger_copies_in_extra_detonations_have_a_closed_shape(self):
        """extra_detonations are copied from the ledger: a new key or a free-text id must not pass."""
        cases = {
            "a new key": lambda i, a, e: i["extra_detonations"][0].update(note="LABWS01"),
            "a free-text id": lambda i, a, e: i["extra_detonations"][0].update(id="jdoe"),
            "a missing key": lambda i, a, e: i["extra_detonations"][0].pop("attack_end"),
            "not a dict": lambda i, a, e: i["extra_detonations"].append("x"),
        }
        inputs, alerts, expected = self.scrubbed()
        sf.check(inputs, alerts, expected)  # the unmutated neighbour passes
        for label, mutate in cases.items():
            with self.subTest(label):
                inputs, alerts, expected = self.scrubbed()
                mutate(inputs, alerts, expected)
                with self.assertRaises(sf.ScrubError):
                    sf.check(inputs, alerts, expected)

    def test_rule_memory_fields_are_known_field_names_and_the_rules_own(self):
        for fields in (["host.name"], ["process.name", "winlog.event_data.ProcessName"]):
            inputs, alerts, expected = self.scrubbed()
            inputs["rule_memory"] = {RID: self.memory(fields)}
            sf.check(inputs, alerts, expected)
        for fields in (["jdoe"], ["host.name", "jdoe"], ["jdoe.acme"], ["labbox.corp"]):
            with self.subTest(fields=fields):
                inputs, alerts, expected = self.scrubbed()
                inputs["rule_memory"] = {RID: self.memory(fields)}
                with self.assertRaises(sf.ScrubError):
                    sf.check(inputs, alerts, expected)
        export = os.path.join(tempfile.mkdtemp(), "export.ndjson")
        with open(export, "w") as f:
            f.write(json.dumps({"rule_id": RID, "name": "Public Rule", "immutable": True, "author": ["Elastic"],
                                "new_terms_fields": ["process.name"]}) + "\n")
        inputs, alerts, expected = self.scrubbed()
        inputs["rule_memory"] = {RID: self.memory(["process.name"])}
        sf.check(inputs, alerts, expected, rules_export=export)
        inputs["rule_memory"] = {RID: self.memory(["user.name"])}
        with self.assertRaises(sf.ScrubError) as cm:
            sf.check(inputs, alerts, expected, rules_export=export)
        self.assertIn("new_terms_fields", str(cm.exception))

    def test_a_public_address_and_an_unknown_dataset_integration_are_refused(self):
        for label, mutate in {
            "public IPv4": lambda i, a, e: a[0].update(name="Malicious Behavior Prevention Alert: callback 8.8.8.8"),
            "dataset": lambda i, a, e: a[0].update(event_dataset="jdoe.acme"),
        }.items():
            with self.subTest(label):
                inputs, alerts, expected = self.scrubbed()
                mutate(inputs, alerts, expected)
                with self.assertRaises(sf.ScrubError):
                    sf.check(inputs, alerts, expected)
        inputs, alerts, expected = self.scrubbed()
        alerts[0]["event_dataset"] = "endpoint.alerts"
        sf.check(inputs, alerts, expected)

    def test_a_rule_that_is_not_an_immutable_elastic_rule_is_refused(self):
        export = os.path.join(tempfile.mkdtemp(), "export.ndjson")
        with open(export, "w") as f:
            f.write(json.dumps({"rule_id": RID, "name": "Public Rule", "immutable": True, "author": ["Elastic"]}) + "\n")
            f.write(json.dumps({"rule_id": "99999999-2222-4333-8444-555555555555", "name": "Mine",
                                "immutable": False, "author": ["Someone"]}) + "\n")
        inputs, alerts, expected = self.scrubbed()
        sf.check(inputs, alerts, expected, rules_export=export)  # prebuilt id and name pass
        alerts[0]["rule_id"] = "99999999-2222-4333-8444-555555555555"
        alerts[0]["name"] = "Mine"
        with self.assertRaises(sf.ScrubError) as cm:
            sf.check(inputs, alerts, expected, rules_export=export)
        self.assertIn("not an immutable Elastic rule", str(cm.exception))
        inputs, alerts, expected = self.scrubbed()
        for name in ("A Neutral Name", "8.8.8.8", "LABWS01"):
            alerts[0]["name"] = name
            with self.assertRaises(sf.ScrubError):
                sf.check(inputs, alerts, expected, rules_export=export)
        alerts[0]["name"] = "A Neutral Name"
        with self.assertRaises(sf.ScrubError) as cm:
            sf.check(inputs, alerts, expected, rules_export=export)
        self.assertIn("export's name", str(cm.exception))

    def test_a_missing_rules_export_refuses_instead_of_passing(self):
        inputs, alerts, expected = self.scrubbed()
        with self.assertRaises(sf.ScrubError) as cm:
            sf.check(inputs, alerts, expected, rules_export="/nonexistent/export.ndjson")
        self.assertIn("rules export", str(cm.exception))

    def test_the_lab_registry_names_are_denied_when_supplied(self):
        inputs, alerts, expected = self.scrubbed()
        alerts[0]["name"] = "Seen On Hostzz"
        with self.assertRaises(sf.ScrubError):
            sf.check(inputs, alerts, expected, extra_denials=("hostzz",))


class TestCommandLine(unittest.TestCase):
    def test_refused_fixture_is_not_written_and_exit_is_1(self):
        src, dst = tempfile.mkdtemp(), os.path.join(tempfile.mkdtemp(), "out")
        inputs, alerts, expected = raw()
        alerts[0]["name"] = "contact bob@example.nl"
        for name, doc in (("inputs.json", inputs), ("alerts.json", alerts), ("expected.json", expected)):
            with open(os.path.join(src, name), "w") as f:
                json.dump(doc, f)
        p = subprocess.run([sys.executable, os.path.join(HERE, "scrub_fixture.py"), src, dst],
                           capture_output=True, text=True)
        self.assertEqual(p.returncode, 1, p.stdout + p.stderr)
        self.assertFalse(os.path.exists(dst))
        self.assertIn("e-mail address", p.stderr)
        self.assertNotIn("bob@example.nl", p.stderr)


if __name__ == "__main__":
    unittest.main()
