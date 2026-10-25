# rules/engine/test_new_terms_memory.py
"""2026-10-22: two things the nightly of that morning got wrong, and must not again.

1. A building-block rule's own alert is a target hit. Only a sequence's components
   (group id and building-block marker) are skipped.
2. A new-terms rule remembers a host. Re-running inside that memory window cannot
   produce a new alert, so the verifier must not report a detection gap. The
   verifier now says INCONCLUSIVE with the reason when the record proves the memory,
   and the selector keeps such a use-case out of the rotation for window + 1 day.
"""
import json
import os
import tempfile
import unittest
from datetime import datetime, timezone, timedelta
from unittest import mock

import selector as sel
from loader import new_terms_memory_seconds, parse_relative_window
from result import make_result, Verdict
from ruleid import load_enabled_rules
from verify import (classify, is_sequence_component, memory_is_host_bound, memory_evidence,
                    memory_reason)
import run as runmod

T0 = datetime(2026, 10, 22, 4, 4, 32, tzinfo=timezone.utc)
INTERVALS = {"ping": "5m"}
HOST = {"name": "lab-host", "id": "00000000-0000-4000-8000-0000000000a2"}


def uc(**kw):
    base = {"id": "discovery/ping", "rule_ids": ["ping"], "executor": "winrm_command"}
    base.update(kw)
    return base


def result(attack_start=T0):
    return make_result(uc(), "EXECUTED", True, attack_start=attack_start.isoformat(),
                       attack_end=(attack_start + timedelta(seconds=1)).isoformat(), host=dict(HOST))


def alert(rule_id, ts, **kw):
    a = {"rule_id": rule_id, "name": "Rule", "host_name": "lab-host", "host_id": HOST["id"],
         "event_type": ["start"], "@timestamp": ts.isoformat(), "original_time": ts.isoformat(),
         "group_id": None, "building_block_type": None}
    a.update(kw)
    return a


class TestBuildingBlockRuleAlertIsAHit2026_10_22(unittest.TestCase):
    def test_a_building_block_rules_own_alert_is_detected(self):
        a = alert("ping", T0 + timedelta(seconds=62), building_block_type="default")
        now = T0 + timedelta(minutes=10)
        self.assertIs(classify(result(), [a], now, INTERVALS), Verdict.DETECTED)

    def test_a_sequence_component_is_still_not_a_hit(self):
        a = alert("ping", T0 + timedelta(seconds=62), building_block_type="default",
                  group_id="g1", group_index=0)
        now = T0 + timedelta(minutes=10)
        self.assertIsNot(classify(result(), [a], now, INTERVALS), Verdict.DETECTED)

    def test_is_sequence_component_needs_both_marks(self):
        self.assertTrue(is_sequence_component({"group_id": "g", "building_block_type": "default"}))
        self.assertFalse(is_sequence_component({"group_id": None, "building_block_type": "default"}))
        self.assertFalse(is_sequence_component({"group_id": "g", "building_block_type": None}))
        self.assertFalse(is_sequence_component({}))


class TestNewTermsMemory(unittest.TestCase):
    def test_window_parsing(self):
        self.assertEqual(parse_relative_window("now-5d"), 432000)
        self.assertEqual(parse_relative_window("now-12h"), 43200)
        self.assertEqual(parse_relative_window(" now-30m "), 1800)
        self.assertIsNone(parse_relative_window("5d"))
        self.assertIsNone(parse_relative_window("now-5w"))
        self.assertIsNone(parse_relative_window(None))
        self.assertEqual(new_terms_memory_seconds({"type": "new_terms", "history_window_start": "now-7d"}), 604800)
        self.assertIsNone(new_terms_memory_seconds({"type": "eql", "history_window_start": "now-7d"}))
        self.assertIsNone(new_terms_memory_seconds({"type": "new_terms"}))
        self.assertIsNone(new_terms_memory_seconds(None))

    def test_host_bound_fields(self):
        self.assertTrue(memory_is_host_bound(["host.id"]))
        self.assertTrue(memory_is_host_bound(["host.id", "user.id"]))
        self.assertFalse(memory_is_host_bound(["host.id", "process.command_line"]))
        self.assertFalse(memory_is_host_bound(["process.executable"]))
        self.assertFalse(memory_is_host_bound([]))
        self.assertFalse(memory_is_host_bound(None))

    def test_evidence_from_a_prior_detonation_inside_the_window(self):
        prior = [
            {"attack_start": (T0 - timedelta(days=1)).isoformat(), "rule_ids": ["ping"], "id": "discovery/ping"},
            {"attack_start": (T0 - timedelta(days=6)).isoformat(), "rule_ids": ["ping"], "id": "old"},
            # tonight's own row: not "prior"
            {"attack_start": T0.isoformat(), "rule_ids": ["ping"], "id": "discovery/ping"},
        ]
        ev = memory_evidence(result(), "ping", 5 * 86400, None, prior)
        self.assertEqual(ev["source"], "detonation")
        self.assertEqual(ev["usecase"], "discovery/ping")
        self.assertEqual(ev["at"], (T0 - timedelta(days=1)).isoformat())

    def test_evidence_from_the_rules_own_alert_at_behaviour_time(self):
        a = alert("ping", T0 - timedelta(days=2), building_block_type="default")
        ev = memory_evidence(result(), "ping", 5 * 86400, [a], [])
        self.assertEqual(ev["source"], "alert")
        self.assertIsNone(ev["usecase"])

    def test_no_evidence_outside_the_window_or_for_another_rule(self):
        alerts = [alert("other", T0 - timedelta(days=1)),
                  alert("ping", T0 - timedelta(days=5, seconds=1))]
        prior = [{"attack_start": (T0 - timedelta(days=5, seconds=1)).isoformat(),
                  "rule_ids": ["ping"], "id": "x"},
                 {"attack_start": (T0 - timedelta(days=1)).isoformat(), "rule_ids": ["other"], "id": "y"}]
        self.assertIsNone(memory_evidence(result(), "ping", 5 * 86400, alerts, prior))
        self.assertIsNone(memory_evidence(result(), "ping", None, alerts, prior))

    def test_the_latest_evidence_wins(self):
        prior = [{"attack_start": (T0 - timedelta(days=3)).isoformat(), "rule_ids": ["ping"], "id": "older"}]
        alerts = [alert("ping", T0 - timedelta(days=1))]
        ev = memory_evidence(result(), "ping", 5 * 86400, alerts, prior)
        self.assertEqual(ev["source"], "alert")

    def test_reason_text_names_rule_fields_window_host_and_evidence(self):
        txt = memory_reason("Rule", "ping", ["host.id"], "now-5d", "lab-host",
                            {"source": "detonation", "at": "2026-10-21T04:04:37+00:00", "usecase": "d/x"})
        self.assertIn("Rule is a new-terms rule keyed on host.id with a now-5d memory", txt)
        self.assertIn("lab-host already matched on 2026-10-21T04:04:37+00:00 (detonation: d/x)", txt)
        txt2 = memory_reason(None, "ping", [], None, None, {"source": "alert", "at": "t"})
        self.assertIn("ping", txt2)
        self.assertIn("the rule's own alert", txt2)


class TestRunMemoryCheck(unittest.TestCase):
    MEMORY = {"ping": {"name": "Ping Rule", "fields": ["host.id"], "window": "now-5d", "window_s": 432000}}
    HOSTS = {"names": ["lab-host"], "ids": [HOST["id"]]}

    def test_a_missed_against_a_remembered_host_becomes_inconclusive_with_the_reason(self):
        r = result()
        r.verdict = Verdict.MISSED
        prior = [{"attack_start": (T0 - timedelta(days=1)).isoformat(), "rule_ids": ["ping"], "id": "discovery/ping"}]
        with mock.patch.object(runmod, "_rule_memory_by_rule_id", return_value=self.MEMORY), \
                mock.patch.object(runmod.verifymod, "query_alerts", return_value=[]) as q:
            runmod._apply_memory_check(r, HOST, self.HOSTS, "https://es", "key", prior)
        self.assertIs(r.verdict, Verdict.INCONCLUSIVE)
        self.assertIn("rule memory: Ping Rule", r.verdict_reason)
        self.assertIn("lab-host already matched", r.verdict_reason)
        q.assert_called_once()
        self.assertEqual(q.call_args[0][2], ["ping"])
        self.assertEqual(q.call_args[0][3], (T0 - timedelta(days=5)).isoformat())
        self.assertEqual(q.call_args[0][4], self.HOSTS)

    def test_the_rules_own_prior_alert_is_evidence_too(self):
        r = result()
        r.verdict = Verdict.MISSED
        prior_alert = [alert("ping", T0 - timedelta(days=2), building_block_type="default")]
        with mock.patch.object(runmod, "_rule_memory_by_rule_id", return_value=self.MEMORY), \
                mock.patch.object(runmod.verifymod, "query_alerts", return_value=prior_alert):
            runmod._apply_memory_check(r, HOST, self.HOSTS, "https://es", "key", [])
        self.assertIs(r.verdict, Verdict.INCONCLUSIVE)
        self.assertIn("(alert: the rule's own alert)", r.verdict_reason)

    def test_a_rule_keyed_on_a_payload_field_is_left_missed(self):
        r = result()
        r.verdict = Verdict.MISSED
        memory = {"ping": {"name": "Ping Rule", "fields": ["host.id", "process.command_line"],
                           "window": "now-7d", "window_s": 604800}}
        prior = [{"attack_start": (T0 - timedelta(days=1)).isoformat(), "rule_ids": ["ping"], "id": "discovery/ping"}]
        with mock.patch.object(runmod, "_rule_memory_by_rule_id", return_value=memory), \
                mock.patch.object(runmod.verifymod, "query_alerts", return_value=[]) as q:
            runmod._apply_memory_check(r, HOST, self.HOSTS, "https://es", "key", prior)
        self.assertIs(r.verdict, Verdict.MISSED)
        self.assertIsNone(r.verdict_reason)
        q.assert_not_called()

    def test_no_evidence_leaves_missed_and_no_credentials_still_reads_the_ledger(self):
        r = result()
        r.verdict = Verdict.MISSED
        with mock.patch.object(runmod, "_rule_memory_by_rule_id", return_value=self.MEMORY), \
                mock.patch.object(runmod.verifymod, "query_alerts", return_value=[]):
            runmod._apply_memory_check(r, HOST, self.HOSTS, "https://es", "key", [])
        self.assertIs(r.verdict, Verdict.MISSED)
        self.assertIsNone(r.verdict_reason)
        r2 = result()
        r2.verdict = Verdict.MISSED
        prior = [{"attack_start": (T0 - timedelta(days=1)).isoformat(), "rule_ids": ["ping"], "id": "discovery/ping"}]
        with mock.patch.object(runmod, "_rule_memory_by_rule_id", return_value=self.MEMORY), \
                mock.patch.object(runmod.verifymod, "query_alerts") as q:
            runmod._apply_memory_check(r2, HOST, self.HOSTS, None, None, prior)
        self.assertIs(r2.verdict, Verdict.INCONCLUSIVE)
        q.assert_not_called()

    def test_ledger_rows_carry_the_reason_only_when_set(self):
        r = result()
        r.verdict = Verdict.INCONCLUSIVE
        r.verdict_reason = "rule memory: x"
        self.assertEqual(runmod._ledger_row(r, "t0")["verdict_reason"], "rule memory: x")
        self.assertEqual(runmod._recheck_ledger_row(r, {"run_ts": "t0"}, T0)["verdict_reason"], "rule memory: x")
        self.assertEqual(r.to_dict()["verdict_reason"], "rule memory: x")
        r2 = result()
        r2.verdict = Verdict.MISSED
        self.assertNotIn("verdict_reason", runmod._ledger_row(r2, "t0"))
        self.assertNotIn("verdict_reason", runmod._recheck_ledger_row(r2, {"run_ts": "t0"}, T0))

    def test_the_memory_map_reads_only_new_terms_rules_from_the_pack(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "rules_export.sample.ndjson")
            with open(p, "w") as f:
                f.write(json.dumps({"name": "NT", "rule_id": "nt-1", "enabled": True, "interval": "5m",
                                    "from": "now-9m", "type": "new_terms", "query": "x",
                                    "new_terms_fields": ["host.id"], "history_window_start": "now-5d"}) + "\n")
                f.write(json.dumps({"name": "E", "rule_id": "e-1", "enabled": True, "interval": "5m",
                                    "from": "now-9m", "type": "eql", "query": "y"}) + "\n")
            runmod._rule_memory_by_rule_id.cache_clear()
            m = runmod._rule_memory_by_rule_id(p)
        self.assertEqual(m, {"nt-1": {"name": "NT", "fields": ["host.id"], "window": "now-5d", "window_s": 432000}})


class TestSelectorCooldown(unittest.TestCase):
    NOW = datetime(2026, 10, 23, 2, 0, tzinfo=timezone.utc)

    def u(self, uid, memory=None):
        d = {"id": uid, "severity": "MEDIUM", "safety": "safe", "expect": "detected"}
        if memory:
            d["rule_memory_s"] = memory
        return d

    def row(self, uid, days_ago, verdict):
        return {"id": uid, "run_ts": (self.NOW - timedelta(days=days_ago)).isoformat(), "verdict": verdict}

    def test_a_use_case_inside_its_rules_memory_is_not_selected_even_as_a_regression(self):
        cases = [self.u("d/msbuild", memory=5 * 86400), self.u("d/other")]
        rows = [self.row("d/msbuild", 20, "DETECTED"), self.row("d/msbuild", 1, "MISSED"),
                self.row("d/other", 30, "DETECTED")]
        ids, meta = sel.select_nightly(cases, rows, 5, now=self.NOW)
        self.assertNotIn("d/msbuild", ids)
        self.assertEqual(ids, ["d/other"])
        self.assertEqual(meta["cooldown"], 1)
        self.assertEqual(meta["cooldown_ids"], ["d/msbuild"])
        self.assertEqual(meta["pool"], 1)

    def test_the_margin_is_one_day_past_the_window(self):
        e = {"last_run_ts": (self.NOW - timedelta(days=5, hours=23)).isoformat()}
        self.assertTrue(sel.in_rule_memory(self.u("x", 5 * 86400), e, self.NOW))
        e2 = {"last_run_ts": (self.NOW - timedelta(days=6, hours=1)).isoformat()}
        self.assertFalse(sel.in_rule_memory(self.u("x", 5 * 86400), e2, self.NOW))

    def test_no_memory_or_never_run_is_never_cooling(self):
        self.assertFalse(sel.in_rule_memory(self.u("x"), {"last_run_ts": self.NOW.isoformat()}, self.NOW))
        self.assertFalse(sel.in_rule_memory(self.u("x", 100), None, self.NOW))
        self.assertFalse(sel.in_rule_memory(self.u("x", 100), {"last_run_ts": None}, self.NOW))

    def test_once_the_window_has_passed_the_standing_missed_lane_takes_it_again(self):
        cases = [self.u("d/msbuild", memory=5 * 86400)]
        rows = [self.row("d/msbuild", 20, "DETECTED"), self.row("d/msbuild", 7, "MISSED")]
        ids, meta = sel.select_nightly(cases, rows, 5, now=self.NOW)
        self.assertEqual(ids, ["d/msbuild"])
        self.assertEqual(meta["cooldown"], 0)
        self.assertEqual(meta["cooldown_ids"], [])


class TestRuleIdAndLoaderKeepTheMemory(unittest.TestCase):
    def test_load_enabled_rules_keeps_type_fields_and_window(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "rules_export.sample.ndjson")
            with open(p, "w") as f:
                f.write(json.dumps({"name": "NT", "rule_id": "nt-1", "enabled": True, "interval": "5m",
                                    "from": "now-9m", "type": "new_terms", "query": "x",
                                    "new_terms_fields": ["host.id"], "history_window_start": "now-5d"}) + "\n")
                f.write(json.dumps({"name": "E", "rule_id": "e-1", "enabled": True, "interval": "5m",
                                    "from": "now-9m", "type": "eql", "query": "y"}) + "\n")
            rules = load_enabled_rules(p)
        self.assertEqual(rules["NT"]["type"], "new_terms")
        self.assertEqual(rules["NT"]["new_terms_fields"], ["host.id"])
        self.assertEqual(rules["NT"]["history_window_start"], "now-5d")
        self.assertEqual(rules["E"]["new_terms_fields"], [])
        self.assertIsNone(rules["E"]["history_window_start"])
        self.assertEqual(new_terms_memory_seconds(rules["NT"]), 432000)
        self.assertIsNone(new_terms_memory_seconds(rules["E"]))

if __name__ == "__main__":
    unittest.main()
