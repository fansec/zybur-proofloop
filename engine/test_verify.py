# rules/engine/test_verify.py
import json
import unittest
import urllib.request
from datetime import datetime, timezone, timedelta
import testenv
from result import make_result, Verdict, PRECEDENCE, worst
from verify import (classify, due_time, parse_interval_to_seconds, is_prevention,
                    co_firing_for, build_alert_query, behavior_ts, next_start_bound,
                    _flat, query_alerts, contested_rule_ids)

def setUpModule():
    testenv.use_fixture_lab_hosts_for_module()
    testenv.use_sample_pack_for_module()


def uc(**kw):
    base = {"id": "c/x", "rule_ids": ["r1"], "executor": "e"}; base.update(kw); return base

T0 = datetime(2026, 7, 25, 12, 0, 0, tzinfo=timezone.utc)
INTERVALS = {"r1": "5m"}

def alert(rule_id, minutes, name="Some Rule", event_type=None, host_name="production"):
    return {"rule_id": rule_id, "name": name, "host_name": host_name, "host_id": None,
            "event_type": event_type or ["start"],
            "@timestamp": (T0 + timedelta(minutes=minutes)).isoformat()}

class TestVerify(unittest.TestCase):
    def test_parse_interval(self):
        self.assertEqual(parse_interval_to_seconds("5m"), 300)
        self.assertEqual(parse_interval_to_seconds("12h"), 43200)

    def test_abort_when_not_executed(self):
        r = make_result(uc(), "NO_AGENT", False)
        self.assertIs(classify(r, [], T0, INTERVALS), Verdict.ABORT)

    def test_inconclusive_when_alerts_none(self):
        r = make_result(uc(), "SUCCESS", True, attack_start=T0.isoformat(), attack_end=T0.isoformat())
        self.assertIs(classify(r, None, T0, INTERVALS), Verdict.INCONCLUSIVE)

    def test_detected_when_alert_after_attack_start(self):
        r = make_result(uc(), "SUCCESS", True, attack_start=T0.isoformat(), attack_end=T0.isoformat())
        now = T0 + timedelta(minutes=10)
        self.assertIs(classify(r, [alert("r1", 6)], now, INTERVALS), Verdict.DETECTED)

    def test_pending_before_due(self):
        r = make_result(uc(), "SUCCESS", True, attack_start=T0.isoformat(), attack_end=T0.isoformat())
        now = T0 + timedelta(minutes=1)  # < 5m + 120s
        self.assertIs(classify(r, [], now, INTERVALS), Verdict.PENDING)

    def test_missed_after_due_with_no_alert(self):
        r = make_result(uc(), "SUCCESS", True, attack_start=T0.isoformat(), attack_end=T0.isoformat())
        now = T0 + timedelta(minutes=10)  # > 5m + 120s
        self.assertIs(classify(r, [], now, INTERVALS), Verdict.MISSED)

    # --- PREVENTED ---------------------------------------------------------

    def test_is_prevention_reads_event_type_denied(self):
        # Measured live 2026-07-25: every Defend prevention carries event.type "denied".
        self.assertTrue(is_prevention(alert("9a1a", 1, event_type=["info", "denied"])))
        self.assertFalse(is_prevention(alert("r1", 1, event_type=["start", "end"])))

    def test_a_denied_windows_event_under_a_detection_rule_is_not_a_prevention(self):
        """2026-10-14: the WFP rule's alert (dataset system.security, event.type
        [connection, info, denied]) graded a neighbouring DC1 row PREVENTED."""
        wfp = alert("92d3", 1, event_type=["connection", "info", "denied"])
        wfp["event_dataset"] = "system.security"
        wfp["name"] = "Network Policy Rule"
        self.assertFalse(is_prevention(wfp))
        defend = alert("9a1a", 1, event_type=["info", "denied"])
        defend["event_dataset"] = "endpoint.alerts"
        self.assertTrue(is_prevention(defend))
        named = alert("9a1b", 1, event_type=["info"])
        named["event_dataset"] = "endpoint.alerts"
        named["name"] = "Malware Prevention Alert"
        self.assertTrue(is_prevention(named))

    def test_is_prevention_falls_back_to_the_rule_name_prefix(self):
        a = alert("9a1a", 1, name="Malicious Behavior Prevention Alert: RunDLL32 with Unusual Arguments")
        self.assertTrue(is_prevention(a))

    def test_prevented_when_target_silent_but_a_prevention_fired(self):
        r = make_result(uc(), "SUCCESS", True, attack_start=T0.isoformat(), attack_end=T0.isoformat())
        alerts = [alert("9a1a", 1, name="Malicious Behavior Prevention Alert: X", event_type=["info", "denied"])]
        now = T0 + timedelta(minutes=10)
        self.assertIs(classify(r, alerts, now, INTERVALS), Verdict.PREVENTED)

    def test_detected_outranks_prevented(self):
        r = make_result(uc(), "SUCCESS", True, attack_start=T0.isoformat(), attack_end=T0.isoformat())
        alerts = [alert("r1", 6), alert("9a1a", 1, event_type=["info", "denied"])]
        now = T0 + timedelta(minutes=10)
        self.assertIs(classify(r, alerts, now, INTERVALS), Verdict.DETECTED)

    # A prevention seen before the target rule is due is NOT yet a conclusion: the
    # rule may still fire. Concluding PREVENTED early would lose a real DETECTED,
    # and nothing re-checks a row that is not PENDING.
    def test_prevention_before_the_rule_is_due_stays_pending(self):
        r = make_result(uc(), "SUCCESS", True, attack_start=T0.isoformat(), attack_end=T0.isoformat())
        alerts = [alert("9a1a", 0, event_type=["info", "denied"])]
        now = T0 + timedelta(minutes=1)
        self.assertIs(classify(r, alerts, now, INTERVALS), Verdict.PENDING)

    def test_prevention_on_another_host_does_not_count(self):
        r = make_result(uc(), "SUCCESS", True, attack_start=T0.isoformat(), attack_end=T0.isoformat(),
                        host={"name": "production", "id": None})
        alerts = [alert("9a1a", 1, event_type=["info", "denied"], host_name="laptop-jfk3")]
        now = T0 + timedelta(minutes=10)
        self.assertIs(classify(r, alerts, now, INTERVALS), Verdict.MISSED)

    def test_prevention_before_attack_start_does_not_count(self):
        r = make_result(uc(), "SUCCESS", True, attack_start=T0.isoformat(), attack_end=T0.isoformat())
        alerts = [alert("9a1a", -30, event_type=["info", "denied"])]
        now = T0 + timedelta(minutes=10)
        self.assertIs(classify(r, alerts, now, INTERVALS), Verdict.MISSED)

    # --- expect: env_gap / not_enabled --------------------------------------

    def test_env_gap_is_inconclusive_never_missed(self):
        # The rule is deliberately absent. Reporting that as a detection failure
        # would make the loop's one number a lie.
        r = make_result(uc(rule_ids=[], expect="env_gap"), "SUCCESS", True,
                        attack_start=T0.isoformat(), attack_end=T0.isoformat())
        now = T0 + timedelta(hours=2)
        self.assertIs(classify(r, [], now, INTERVALS), Verdict.INCONCLUSIVE)

    def test_not_enabled_is_inconclusive(self):
        r = make_result(uc(rule_ids=[], expect="not_enabled"), "SUCCESS", True,
                        attack_start=T0.isoformat(), attack_end=T0.isoformat())
        self.assertIs(classify(r, [], T0 + timedelta(hours=2), INTERVALS), Verdict.INCONCLUSIVE)

    # A use-case with expect: detected whose rules resolved to nothing has no due
    # time at all. Falling through to MISSED would invent a measurement.
    def test_detected_expectation_with_no_rule_ids_is_inconclusive(self):
        r = make_result(uc(rule_ids=[]), "SUCCESS", True,
                        attack_start=T0.isoformat(), attack_end=T0.isoformat())
        self.assertIs(classify(r, [], T0 + timedelta(hours=2), INTERVALS), Verdict.INCONCLUSIVE)

    # --- precedence ---------------------------------------------------------

    def test_precedence_is_the_spec_ordering(self):
        order = [Verdict.ABORT, Verdict.INCONCLUSIVE, Verdict.DETECTED,
                 Verdict.PREVENTED, Verdict.PENDING, Verdict.MISSED]
        self.assertEqual(sorted(order, key=PRECEDENCE.get), order)

    def test_worst_picks_the_highest_precedence(self):
        self.assertIs(worst([Verdict.MISSED, Verdict.DETECTED]), Verdict.DETECTED)
        self.assertIs(worst([Verdict.PENDING, Verdict.PREVENTED]), Verdict.PREVENTED)
        self.assertIs(worst([Verdict.DETECTED, Verdict.ABORT]), Verdict.ABORT)
        self.assertIsNone(worst([]))

    # --- co_firing ----------------------------------------------------------

    def test_co_firing_is_every_other_alert_on_the_host_in_the_window(self):
        r = make_result(uc(), "SUCCESS", True, attack_start=T0.isoformat(), attack_end=T0.isoformat(),
                        host={"name": "production", "id": None})
        alerts = [
            alert("r1", 6, name="Target Rule"),                 # the target: excluded
            alert("9a1a", 1, name="Prevention A", event_type=["info", "denied"]),
            alert("00140285", 3, name="Other Detection"),
            alert("9a1a", 1, name="Elsewhere", host_name="laptop-jfk3"),  # other host: excluded
            alert("9a1a", -30, name="Before"),                  # before attack_start: excluded
        ]
        cf = co_firing_for(r, alerts, INTERVALS)
        self.assertEqual([c["name"] for c in cf], ["Prevention A", "Other Detection"])
        self.assertEqual(set(cf[0]), {"rule_id", "name", "ts", "prevented"})
        self.assertTrue(cf[0]["prevented"])
        self.assertFalse(cf[1]["prevented"])

    def test_co_firing_is_empty_when_alerts_could_not_be_read(self):
        r = make_result(uc(), "SUCCESS", True, attack_start=T0.isoformat(), attack_end=T0.isoformat())
        self.assertEqual(co_firing_for(r, None, INTERVALS), [])

    # --- the widened query --------------------------------------------------

    def test_query_asks_for_the_host_as_well_as_the_rule_ids(self):
        body = build_alert_query(["r1", "r2"], "2026-07-25T12:00:00+00:00",
                                 {"names": ["production"], "ids": ["0000a1a1"]})
        self.assertEqual(body["query"]["bool"]["minimum_should_match"], 1)
        shoulds = body["query"]["bool"]["should"]
        self.assertIn({"terms": {"kibana.alert.rule.rule_id": ["r1", "r2"]}}, shoulds)
        self.assertIn({"terms": {"host.name": ["production"]}}, shoulds)
        self.assertIn({"terms": {"host.id": ["0000a1a1"]}}, shoulds)
        # co_firing needs the name and event.type, or a prevention is unreadable
        for f in ("kibana.alert.rule.name", "event.type", "host.name"):
            self.assertIn(f, body["_source"])
        # attribution needs the behavior time: Defend batch-writes preventions
        # (measured 2026-07-26: @timestamp 19s after the behavior it blocked)
        self.assertIn("kibana.alert.original_time", body["_source"])
        self.assertIn("event.ingested", body["_source"])

    def test_query_omits_an_empty_host_clause_rather_than_matching_everything(self):
        body = build_alert_query(["r1"], "2026-07-25T12:00:00+00:00", {"names": [], "ids": []})
        self.assertEqual(body["query"]["bool"]["should"],
                         [{"terms": {"kibana.alert.rule.rule_id": ["r1"]}}])


class TestLsassRegression2026_07_25(unittest.TestCase):
    """The measured run this whole verdict change exists for.

    2026-07-25 17:44:14Z, credential-access/lsass-memory-dump-creation detonated on
    `production`. Its target rule LSASS Memory Dump Creation
    (f2f46686-6f3c-4724-bd7d-24e31c70f98f) never fired because Defend PREVENTED the
    dump, so the telemetry the rule reads never existed. Two prevention alerts landed
    17 seconds later. The old engine scored this MISSED. It is a success.
    """

    START = "2026-07-25T17:44:14.399187+00:00"
    TARGET = "f2f46686-6f3c-4724-bd7d-24e31c70f98f"
    ALERTS = [
        {"rule_id": "9a1a2dae-0b5f-4c3d-8305-a268d404c306",
         "name": "Malicious Behavior Prevention Alert: RunDLL32 with Unusual Arguments",
         "event_type": ["info", "denied"], "host_name": "production", "host_id": None,
         "@timestamp": "2026-07-25T17:44:31.575Z"},
        {"rule_id": "9a1a2dae-0b5f-4c3d-8305-a268d404c306",
         "name": "Malicious Behavior Prevention Alert: Credential Access via Known Utilities",
         "event_type": ["info", "denied"], "host_name": "production", "host_id": None,
         "@timestamp": "2026-07-25T17:44:31.566Z"},
        {"rule_id": "00140285-b827-4aee-aa09-8113f58a08f3",
         "name": "Context Rule",
         "event_type": ["start", "end"], "host_name": "production", "host_id": None,
         "@timestamp": "2026-07-25T17:46:55.612Z"},
    ]

    def _result(self):
        return make_result(
            {"id": "credential-access/lsass-memory-dump-creation", "rule_ids": [self.TARGET],
             "executor": "caldera_command"},
            "SUCCESS", True, attack_start=self.START, attack_end=self.START,
            host={"name": "production", "id": "00000000-0000-4000-8000-0000000000a1"})

    def test_verdict_is_prevented_not_missed(self):
        now = datetime(2026, 7, 25, 18, 30, tzinfo=timezone.utc)
        v = classify(self._result(), self.ALERTS, now, {self.TARGET: "5m"})
        self.assertIs(v, Verdict.PREVENTED)

    def test_co_firing_carries_all_three_alerts_with_the_preventions_flagged(self):
        cf = co_firing_for(self._result(), self.ALERTS, {self.TARGET: "5m"})
        self.assertEqual(len(cf), 3)
        self.assertEqual(sum(1 for c in cf if c["prevented"]), 2)


class TestBehaviorTimeAttribution(unittest.TestCase):
    """Findings c0e223be080a + 721ab38ba1a0 (2026-07-26): back-to-back detonations
    share one prevention pool. Measured live: Defend batch-writes prevention alerts
    (@timestamp 09:58:32.510 for a behavior at 09:58:13.869, kibana.alert.original_time
    carries the behavior time), and the alert window had no upper bound at the next
    detonation, so 9 prevention alerts landed in 10 ledger rows across 5 use-cases.
    """

    def _result(self, start_min=0):
        t = (T0 + timedelta(minutes=start_min)).isoformat()
        return make_result(uc(), "SUCCESS", True, attack_start=t, attack_end=t)

    # --- behavior_ts ---------------------------------------------------------

    def test_behavior_ts_prefers_original_time_over_write_time(self):
        a = alert("9a1a", 20)
        a["original_time"] = (T0 + timedelta(minutes=1)).isoformat()
        self.assertEqual(behavior_ts(a), T0 + timedelta(minutes=1))

    def test_behavior_ts_falls_back_to_timestamp(self):
        self.assertEqual(behavior_ts(alert("9a1a", 3)), T0 + timedelta(minutes=3))

    def test_behavior_ts_uses_ingest_time_when_original_time_is_impossibly_future(self):
        # Live DC1 shape, 2026-09-05: the DC was nine hours fast but the DCSync
        # rule used event.ingested and emitted a valid signal. A behavior after its
        # own signal is impossible, so it cannot remain the attribution clock.
        a = alert("r1", 5)
        a["original_time"] = (T0 + timedelta(hours=9)).isoformat()
        a["event_ingested"] = (T0 + timedelta(seconds=15)).isoformat()
        self.assertEqual(behavior_ts(a), T0 + timedelta(seconds=15))

    def test_behavior_ts_uses_write_time_for_future_original_without_ingest_time(self):
        a = alert("r1", 5)
        a["original_time"] = (T0 + timedelta(hours=9)).isoformat()
        self.assertEqual(behavior_ts(a), T0 + timedelta(minutes=5))

    # --- prevention windowed on behavior time --------------------------------

    def test_prevention_batch_written_after_the_window_still_counts(self):
        # The alert was WRITTEN past the due deadline but the behavior it blocked
        # happened during the attack. Windowing on write time loses it.
        r = self._result()
        a = alert("9a1a", 20, event_type=["info", "denied"])
        a["original_time"] = (T0 + timedelta(seconds=30)).isoformat()
        now = T0 + timedelta(minutes=10)
        self.assertIs(classify(r, [a], now, INTERVALS), Verdict.PREVENTED)

    def test_prevention_whose_behavior_predates_the_attack_does_not_count(self):
        r = self._result()
        a = alert("9a1a", 1, event_type=["info", "denied"])
        a["original_time"] = (T0 - timedelta(minutes=30)).isoformat()
        now = T0 + timedelta(minutes=10)
        self.assertIs(classify(r, [a], now, INTERVALS), Verdict.MISSED)

    # --- the next-detonation bound -------------------------------------------

    def test_prevention_from_a_later_detonation_is_not_credited(self):
        # A prevention whose behavior happened after the NEXT use-case started
        # belongs to that use-case, not this one.
        r = self._result()
        until = T0 + timedelta(minutes=2)
        a = alert("9a1a", 3, event_type=["info", "denied"])
        now = T0 + timedelta(minutes=10)
        self.assertIs(classify(r, [a], now, INTERVALS, until=until), Verdict.MISSED)

    def test_prevention_before_the_next_detonation_still_counts(self):
        r = self._result()
        until = T0 + timedelta(minutes=2)
        a = alert("9a1a", 1, event_type=["info", "denied"])
        now = T0 + timedelta(minutes=10)
        self.assertIs(classify(r, [a], now, INTERVALS, until=until), Verdict.PREVENTED)

    def test_co_firing_excludes_alerts_at_or_after_the_next_detonation(self):
        # Finding 721ab38ba1a0's measured case: LSASS's PREVENTED row absorbed the
        # target rule of the NEXT use-case, which fired for a behavior after that
        # use-case's own attack_start.
        r = make_result(uc(), "SUCCESS", True, attack_start=T0.isoformat(),
                        attack_end=T0.isoformat(), host={"name": "production", "id": None})
        until = T0 + timedelta(minutes=2)
        alerts = [
            alert("aaa", 1, name="Mine"),
            alert("bbb", 3, name="The next use-case's"),
        ]
        cf = co_firing_for(r, alerts, INTERVALS, until=until)
        self.assertEqual([c["name"] for c in cf], ["Mine"])

    # --- DETECTED on behavior time -------------------------------------------

    def test_target_alert_for_a_pre_attack_event_is_not_a_detection(self):
        # The rule fired, but on an event from before this attack started. Crediting
        # it would let stale telemetry validate a fresh detonation.
        r = self._result()
        a = alert("r1", 6)
        a["original_time"] = (T0 - timedelta(minutes=30)).isoformat()
        now = T0 + timedelta(minutes=10)
        self.assertIs(classify(r, [a], now, INTERVALS), Verdict.MISSED)

    # --- next_start_bound ----------------------------------------------------

    def test_next_start_bound_picks_the_earliest_later_start(self):
        mine = T0.isoformat()
        starts = [T0.isoformat(),
                  (T0 + timedelta(minutes=5)).isoformat(),
                  (T0 + timedelta(minutes=2)).isoformat(),
                  (T0 - timedelta(minutes=9)).isoformat()]
        self.assertEqual(next_start_bound(mine, starts), T0 + timedelta(minutes=2))

    def test_next_start_bound_is_none_when_nothing_starts_later(self):
        self.assertIsNone(next_start_bound(T0.isoformat(), [T0.isoformat()]))
        self.assertIsNone(next_start_bound(T0.isoformat(), []))
        self.assertIsNone(next_start_bound(None, [T0.isoformat()]))


class TestVerifyResultsWiring(unittest.TestCase):
    """verify_results must bound each result's window at its successor's start,
    including successors known only from the ledger (a separate invocation the same
    night), or the shared-pool defect survives at the seam."""

    def _results(self):
        r1 = make_result({"id": "c/a", "rule_ids": ["r1"], "executor": "e"}, "SUCCESS", True,
                         attack_start=T0.isoformat(), attack_end=T0.isoformat())
        t2 = (T0 + timedelta(minutes=2)).isoformat()
        r2 = make_result({"id": "c/b", "rule_ids": ["r2"], "executor": "e"}, "SUCCESS", True,
                         attack_start=t2, attack_end=t2)
        return r1, r2

    def _run_verify(self, results, alerts, extra_starts, intervals=None):
        import run as runmod
        orig_q, orig_creds = runmod.verifymod.query_alerts, runmod._es_credentials
        runmod.verifymod.query_alerts = lambda *a, **kw: alerts
        runmod._es_credentials = lambda: ("https://es.example", "key")
        try:
            now = T0 + timedelta(minutes=15)
            return runmod.verify_results(list(results), intervals or {"r1": "5m", "r2": "5m"}, now=now,
                                         host={"name": "production", "id": None},
                                         extra_starts=extra_starts)
        finally:
            runmod.verifymod.query_alerts = orig_q
            runmod._es_credentials = orig_creds

    def test_sibling_detonations_bound_each_others_windows(self):
        r1, r2 = self._results()
        prevention = alert("9a1a", 3, event_type=["info", "denied"])
        out = self._run_verify([r1, r2], [prevention], extra_starts=[])
        self.assertIs(out[0].verdict, Verdict.MISSED)      # behavior after r2 started
        self.assertIs(out[1].verdict, Verdict.PREVENTED)   # it is r2's block

    def test_ledger_starts_from_another_invocation_bound_the_window_too(self):
        r1, _ = self._results()
        prevention = alert("9a1a", 3, event_type=["info", "denied"])
        later = (T0 + timedelta(minutes=2)).isoformat()
        out = self._run_verify([r1], [prevention], extra_starts=[later])
        self.assertIs(out[0].verdict, Verdict.MISSED)

    def test_a_detected_row_carries_the_query_hash_of_its_export_rule(self):
        # The call site in verify_results is the only thing that makes rule_query_hashes
        # non-empty in a real run, first-run path and both re-check paths alike.
        import run as runmod
        from rulehash import rule_query_hash
        with open(runmod.EXPORT, encoding="utf-8") as f:
            d = next(json.loads(l) for l in f
                     if l.strip() and json.loads(l).get("rule_id") and json.loads(l).get("enabled"))
        rid = d["rule_id"]
        r = make_result({"id": "c/a", "rule_ids": [rid, "zybur-proofloop-canary"], "executor": "e"},
                        "SUCCESS", True, attack_start=T0.isoformat(), attack_end=T0.isoformat())
        hit = dict(alert(rid, 3), rule_version=d["version"])
        managed = dict(alert("zybur-proofloop-canary", 3), rule_version=1)
        out = self._run_verify([r], [hit, managed], extra_starts=[],
                               intervals={rid: "5m", "zybur-proofloop-canary": "5m"})
        self.assertIs(out[0].verdict, Verdict.DETECTED)
        self.assertEqual(set(out[0].rule_versions), {rid, "zybur-proofloop-canary"})
        # the export rule gets its hash; the managed rule (not in the export) gets no key
        self.assertEqual(out[0].rule_query_hashes, {rid: rule_query_hash(d)})

    def test_a_row_that_is_not_detected_has_no_query_hashes(self):
        r1, _ = self._results()
        out = self._run_verify([r1], [], extra_starts=[])
        self.assertIs(out[0].verdict, Verdict.MISSED)
        self.assertEqual(out[0].rule_query_hashes, {})


class TestAdjacentWindowsDoNotOverlap(unittest.TestCase):
    """A window ends at its successor's FLOOR (next start - CLOCK_SKEW_S), not its start.

    Before 2026-10-14 a row's `until` was the next attack_start while the next row's
    floor was its attack_start - 5s, so an alert in those 5s was stored on both rows
    and a row with no alert of its own read PREVENTED on its neighbour's block.
    The replay is the live 2026-10-11 pair from the ledger: mshta (start
    04:04:20.199Z, end 04:04:20.562Z), then suspicious-powershell-engine-imageload
    (start 04:04:30.613Z, end 04:04:34.318Z), whose test_psengine.exe was blocked at
    behavior time 04:04:30.571Z, 42 ms before its own start by the engine clock.
    """

    D = datetime(2026, 10, 11, 4, 4, 0, tzinfo=timezone.utc)
    MSHTA = {"id": "defense-evasion/sample-a",
             "rule_ids": ["181f6b23-3799-445e-9589-0018328a9e46"], "executor": "e"}
    PSENGINE = {"id": "execution/sample-b",
                "rule_ids": ["852c1f19-68e8-43a6-9dce-340771fe1be3"], "executor": "e"}
    RULES = {"181f6b23-3799-445e-9589-0018328a9e46": "5m",
             "852c1f19-68e8-43a6-9dce-340771fe1be3": "5m"}
    HOST = {"name": "production", "id": None}

    def _at(self, s, ms=0):
        return (self.D + timedelta(seconds=s, milliseconds=ms)).isoformat()

    def _rows(self):
        mshta = make_result(self.MSHTA, "SUCCESS", True, attack_start=self._at(20, 199),
                            attack_end=self._at(20, 562), host=dict(self.HOST))
        psengine = make_result(self.PSENGINE, "SUCCESS", True, attack_start=self._at(30, 613),
                               attack_end=self._at(34, 318), host=dict(self.HOST))
        return mshta, psengine

    def _prevention(self, name, behavior, written):
        return {"rule_id": "9a1a2dae-0b5f-4c3d-8305-a268d404c306",
                "name": "Malicious Behavior Prevention Alert: " + name,
                "host_name": "production", "host_id": None, "event_type": ["info", "denied"],
                "original_time": behavior, "@timestamp": written}

    def _psengine_block(self):
        return self._prevention("Execution via Renamed Signed Binary Proxy",
                                self._at(30, 571), self._at(72, 740))

    def _mshta_blocks(self):
        # The ledger keeps only @timestamp (04:05:12.729Z, .735Z); the behavior times
        # here are placed inside mshta's own execution, which is where Defend
        # stopped it.
        return [self._prevention("Suspicious Windows Command Shell Execution",
                                 self._at(20, 330), self._at(72, 729)),
                self._prevention("Suspicious Windows Command Shell Execution",
                                 self._at(20, 335), self._at(72, 735))]

    def _verify(self, results, alerts, starts=(), ends=(), detonations=()):
        import run as runmod
        orig_q, orig_creds = runmod.verifymod.query_alerts, runmod._es_credentials
        runmod.verifymod.query_alerts = lambda *a, **kw: alerts
        runmod._es_credentials = lambda: ("https://es.example", "key")
        try:
            # The extras are passed explicitly, even empty, so the real ledger
            # cannot add starts or ends to the replay.
            return runmod.verify_results(list(results), self.RULES,
                                         now=self.D + timedelta(minutes=16),
                                         host=dict(self.HOST), extra_starts=list(starts),
                                         extra_ends=list(ends),
                                         extra_detonations=list(detonations))
        finally:
            runmod.verifymod.query_alerts = orig_q
            runmod._es_credentials = orig_creds

    def test_the_bound_is_the_successors_floor(self):
        from verify import attribution_until
        mshta, psengine = self._rows()
        self.assertEqual(
            attribution_until(mshta.attack_start, mshta.attack_end, [psengine.attack_start]),
            self.D + timedelta(seconds=25, milliseconds=613))

    def test_the_bound_never_cuts_into_my_own_execution(self):
        # Two detonations closer than CLOCK_SKEW_S: the bound is my own end, which
        # is also where the successor's floor sits (prev_end_bound).
        from verify import attribution_until, prev_end_bound
        start, end, nxt = self._at(0), self._at(3), self._at(4)
        self.assertEqual(attribution_until(start, end, [nxt]), self.D + timedelta(seconds=3))
        self.assertEqual(prev_end_bound(nxt, [end]), self.D + timedelta(seconds=3))
        # No end recorded: the start is the floor, never earlier.
        self.assertEqual(attribution_until(start, None, [self._at(2)]), self.D)

    def test_the_bound_is_none_with_no_later_detonation(self):
        from verify import attribution_until
        self.assertIsNone(attribution_until(self._at(0), self._at(1), [self._at(0)]))
        self.assertIsNone(attribution_until(None, None, [self._at(5)]))

    def test_the_next_attacks_block_lands_only_in_its_own_row(self):
        mshta, psengine = self._rows()
        block = self._psengine_block()
        out = self._verify([mshta, psengine], self._mshta_blocks() + [block])
        mshta_ts = [c["ts"] for c in out[0].co_firing]
        psengine_ts = [c["ts"] for c in out[1].co_firing]
        self.assertNotIn(block["@timestamp"], mshta_ts,
                         "the psengine block was stored on the mshta row before 2026-10-14")
        self.assertEqual(psengine_ts, [block["@timestamp"]])
        self.assertIs(out[0].verdict, Verdict.PREVENTED, "mshta keeps its own two blocks")
        self.assertEqual(len(out[0].co_firing), 2)
        self.assertIs(out[1].verdict, Verdict.PREVENTED)

    def test_a_row_with_no_alert_of_its_own_is_not_PREVENTED_by_the_next(self):
        # The false PREVENTED the overlap could produce: mshta with nothing of its
        # own read PREVENTED on psengine's block until 2026-10-14.
        mshta, psengine = self._rows()
        out = self._verify([mshta, psengine], [self._psengine_block()])
        self.assertIs(out[0].verdict, Verdict.MISSED)
        self.assertEqual(out[0].co_firing, [])
        self.assertIs(out[1].verdict, Verdict.PREVENTED)

    def test_a_successor_known_only_from_the_ledger_bounds_the_same_way(self):
        # The nightly detonates one use-case per invocation, so the successor is
        # usually only in the ledger; the bound must come from there too.
        mshta, psengine = self._rows()
        out = self._verify([mshta], [self._psengine_block()],
                           starts=[psengine.attack_start], ends=[psengine.attack_end],
                           detonations=[{"attack_start": psengine.attack_start,
                                         "attack_end": psengine.attack_end,
                                         "rule_ids": psengine.rule_ids}])
        self.assertIs(out[0].verdict, Verdict.MISSED)
        self.assertEqual(out[0].co_firing, [])

    def test_my_own_uncontested_target_alert_still_passes_the_bound(self):
        # The exemption in _window_alerts is untouched: a late target alert of mine
        # that no later detonation could have produced is still mine.
        mshta, psengine = self._rows()
        late = {"rule_id": self.MSHTA["rule_ids"][0], "name": "mshta rule",
                "host_name": "production", "host_id": None, "event_type": ["start"],
                "original_time": self._at(27), "@timestamp": self._at(90)}
        out = self._verify([mshta, psengine], [late])
        self.assertIs(out[0].verdict, Verdict.DETECTED)


class TestClockSkewLowerBound(unittest.TestCase):
    """attack_start is stamped on the ENGINE host; the alert's behavior time comes
    from the WINDOWS host. The two clocks are not synchronised, and the window's
    lower bound used to have ZERO tolerance while the upper carried EXEC_SLACK_S.

    Measured live 2026-07-28: rule 8b2b3a62 fired on invoice_Q4_2025.pdf.exe with
    kibana.alert.original_time 08:58:09.456Z against an attack_start of
    08:58:09.503976Z - 47.976 ms early - and the run was recorded MISSED over an
    alert sitting in the index. It bites whenever the detectable behavior is the
    FIRST thing the command does, so it is intermittent rather than rare.
    """

    def _res(self, uid="c/a", rid="r1", start=None, end=None):
        s = (start or T0).isoformat()
        e = (end or T0).isoformat()
        return make_result({"id": uid, "rule_ids": [rid], "executor": "e"},
                           "SUCCESS", True, attack_start=s, attack_end=e)

    def test_an_alert_a_few_ms_before_attack_start_is_still_ours(self):
        r = self._res()
        early = {"rule_id": "r1", "name": "n", "host_name": "production", "host_id": None,
                 "event_type": ["start"],
                 "@timestamp": (T0 - timedelta(milliseconds=48)).isoformat()}
        now = T0 + timedelta(minutes=10)
        self.assertIs(classify(r, [early], now, INTERVALS), Verdict.DETECTED)

    def test_the_tolerance_is_seconds_not_minutes(self):
        # Large enough for clock drift, nowhere near a neighbouring detonation.
        r = self._res()
        ancient = {"rule_id": "r1", "name": "n", "host_name": "production", "host_id": None,
                   "event_type": ["start"],
                   "@timestamp": (T0 - timedelta(minutes=5)).isoformat()}
        now = T0 + timedelta(minutes=10)
        self.assertIs(classify(r, [ancient], now, INTERVALS), Verdict.MISSED,
                      "a five-minute-old behavior is a different event, not clock drift")

    def test_the_tolerance_can_never_reach_into_the_PREVIOUS_detonation(self):
        # The whole reason the bound is clamped rather than a flat constant. The
        # previous use-case ended 1s before this one started, well inside the skew
        # tolerance; its alert must stay its own.
        prev_end = T0 - timedelta(seconds=1)
        r = self._res(start=T0, end=T0)
        theirs = {"rule_id": "r1", "name": "n", "host_name": "production", "host_id": None,
                  "event_type": ["start"],
                  "@timestamp": (prev_end - timedelta(seconds=1)).isoformat()}
        now = T0 + timedelta(minutes=10)
        self.assertIs(classify(r, [theirs], now, INTERVALS, since=prev_end), Verdict.MISSED,
                      "an alert from before the previous detonation finished is not ours")

    def test_an_unrelated_predecessor_does_not_clip_my_target_alert(self):
        """Live 2026-09-05: an AD event was 425ms early and an unrelated case
        ended 47ms after that event, so the global clamp hid an existing alert."""
        prev_end = T0 - timedelta(milliseconds=50)
        r = self._res(start=T0, end=T0)
        early = {"rule_id": "r1", "name": "n", "host_name": "production",
                 "host_id": None, "event_type": ["start"],
                 "@timestamp": (T0 - timedelta(milliseconds=100)).isoformat()}
        now = T0 + timedelta(minutes=10)
        self.assertIs(
            classify(r, [early], now, INTERVALS, since=prev_end, target_since={}),
            Verdict.DETECTED)

    def test_a_same_rule_predecessor_still_clips_its_evidence(self):
        prev_end = T0 - timedelta(milliseconds=50)
        r = self._res(start=T0, end=T0)
        early = {"rule_id": "r1", "name": "n", "host_name": "production",
                 "host_id": None, "event_type": ["start"],
                 "@timestamp": (T0 - timedelta(milliseconds=100)).isoformat()}
        now = T0 + timedelta(minutes=10)
        self.assertIs(
            classify(r, [early], now, INTERVALS, since=prev_end,
                     target_since={"r1": prev_end}),
            Verdict.MISSED)

    def test_previous_rule_bounds_choose_only_the_same_rule(self):
        from verify import previous_rule_end_bounds
        detonations = [
            {"attack_end": (T0 - timedelta(seconds=3)).isoformat(), "rule_ids": ["r1"]},
            {"attack_end": (T0 - timedelta(seconds=1)).isoformat(), "rule_ids": ["r2"]},
        ]
        self.assertEqual(
            previous_rule_end_bounds(T0.isoformat(), ["r1"], detonations),
            {"r1": T0 - timedelta(seconds=3)})

    def test_with_no_previous_detonation_the_full_tolerance_applies(self):
        r = self._res()
        early = {"rule_id": "r1", "name": "n", "host_name": "production", "host_id": None,
                 "event_type": ["start"],
                 "@timestamp": (T0 - timedelta(seconds=2)).isoformat()}
        now = T0 + timedelta(minutes=10)
        self.assertIs(classify(r, [early], now, INTERVALS, since=None), Verdict.DETECTED)

    def test_prev_end_bound_picks_the_latest_end_before_mine(self):
        from verify import prev_end_bound
        mine = T0.isoformat()
        ends = [(T0 - timedelta(seconds=30)).isoformat(),
                (T0 - timedelta(seconds=2)).isoformat(),
                (T0 + timedelta(seconds=5)).isoformat()]
        self.assertEqual(prev_end_bound(mine, ends), T0 - timedelta(seconds=2))
        self.assertIsNone(prev_end_bound(mine, []))
        self.assertIsNone(prev_end_bound(None, ends))


if __name__ == "__main__":
    unittest.main()


class TestDetectedBounds(unittest.TestCase):
    """V20 (2026-07-27): the DETECTED branch applied only a lower time bound.

    _window_alerts has applied host scoping and an upper deadline since the
    2026-07-26 behaviour-time attribution fix, and that fix reached PREVENTED and
    co-firing but never the verdict that matters most.
    """

    HOST = {"name": "production", "id": "h1"}

    def _result(self, host=None):
        return make_result(uc(), "SUCCESS", True, attack_start=T0.isoformat(),
                           attack_end=T0.isoformat(), host=host if host is not None else self.HOST)

    def test_detected_still_fires_for_an_alert_on_the_target_host_in_window(self):
        a = alert("r1", 6, host_name="production")
        self.assertIs(classify(self._result(), [a], T0 + timedelta(minutes=10), INTERVALS),
                      Verdict.DETECTED)

    def test_detected_does_not_credit_an_alert_from_another_host(self):
        a = alert("r1", 6, host_name="someone-else")
        a["host_id"] = "h2"
        self.assertIs(classify(self._result(), [a], T0 + timedelta(minutes=10), INTERVALS),
                      Verdict.MISSED)

    def test_esql_aggregate_matches_the_canonical_winlog_alias(self):
        a = alert("r1", 6, host_name=None)
        a["winlog_computer_name"] = "DC1.lab.example"
        result = self._result(host={
            "name": "dc1", "id": "h1", "aliases": ["DC1", "DC1.lab.example"],
        })
        self.assertIs(
            classify(result, [a], T0 + timedelta(minutes=10), INTERVALS),
            Verdict.DETECTED)

    def test_esql_aggregate_from_another_computer_does_not_match(self):
        a = alert("r1", 6, host_name=None)
        a["winlog_computer_name"] = "CUSTOMER-DC.example"
        result = self._result(host={
            "name": "dc1", "id": "h1", "aliases": ["DC1", "DC1.lab.example"],
        })
        self.assertIs(
            classify(result, [a], T0 + timedelta(minutes=10), INTERVALS),
            Verdict.MISSED)

    def test_the_next_detonation_only_takes_my_alert_if_it_targets_my_rule(self):
        # CONTRACT CHANGED 2026-08-05 and BOUNDED 2026-10-24 (D10), and this test is
        # multi-sided so it cannot be "fixed" back by halves.
        #
        # It used to read: "the next use-case started at +3m, so a behavior at +4m
        # belongs to it" - for an alert from r1, which is MY target rule. A use-case
        # that does not target r1 cannot be the owner of an r1 alert; the most it can
        # be is co-firing, and co-firing is recorded separately. Measured across the
        # registry the same day: 176 of 177 target rule ids belong to exactly one
        # use-case, so this clamp was almost never resolving a real contest.
        #
        # What it WAS doing, measured live on 2026-07-29: detonations ran 1-5s apart,
        # so every window was about five seconds wide, and the threshold rule
        # a threshold rule fired for the right
        # detonation on the right host with a bucket-boundary behavior time 4.89s
        # past the clamp. The engine read that alert and recorded MISSED anyway.
        #
        # D10 (the founder, 2026-10-24) bounds that exemption at verify.UNCONTESTED_GRACE_S =
        # CLOCK_SKEW_S: a replay of four recorded nights showed it crediting alerts 26 s to 25
        # minutes past the next detonation's start on attended batch nights (5 of 295
        # detonations, none on a nightly). The measured 2026-07-29 case, 4.89 s past the clamp,
        # is inside the clock-skew tolerance and is still mine; a minute past it is not.
        until = T0 + timedelta(minutes=3)
        skew_tail = alert("r1", 3 + 4.89 / 60, host_name="production")
        self.assertIs(classify(self._result(), [skew_tail], T0 + timedelta(minutes=10), INTERVALS,
                               until=until), Verdict.DETECTED,
                      "nothing later targets r1 and 4.89 s is inside the skew tolerance: mine")

        a = alert("r1", 4, host_name="production")
        self.assertIs(classify(self._result(), [a], T0 + timedelta(minutes=10), INTERVALS,
                               until=until), Verdict.MISSED,
                      "uncontested, but a minute past the next start: not mine since D10")

        contested = classify(self._result(), [skew_tail], T0 + timedelta(minutes=10), INTERVALS,
                             until=until, contested={"r1"})
        self.assertIs(contested, Verdict.MISSED,
                      "a later detonation DOES target r1, so the hard clamp still applies")

    def test_the_exemption_does_not_reach_past_the_due_deadline(self):
        # The uncontested exemption lifts the NEIGHBOUR clamp, never the due bound.
        # Without this, "my rule fired at any point in the last month" would read as
        # a detection of tonight's attack.
        a = alert("r1", 30, host_name="production")
        self.assertIs(classify(self._result(), [a], T0 + timedelta(minutes=40), INTERVALS,
                               until=T0 + timedelta(minutes=3)),
                      Verdict.MISSED)

    def test_the_exemption_does_not_reach_another_host(self):
        # Host scoping is the other bound the exemption must not touch: an alert
        # from my rule on someone else's box is not my detonation.
        a = alert("r1", 4, host_name="someone-else")
        a["host_id"] = "h2"
        self.assertIs(classify(self._result(), [a], T0 + timedelta(minutes=10), INTERVALS,
                               until=T0 + timedelta(minutes=3)),
                      Verdict.MISSED)

    def test_a_non_target_alert_is_still_clamped(self):
        # The exemption is for MY target rule only. Someone else's alert past the
        # clamp stays theirs, which is what keeps co_firing honest.
        a = alert("r9", 4, host_name="production", name="Someone Else's Rule")
        r = self._result()
        self.assertEqual(co_firing_for(r, [a], {"r1": "5m", "r9": "5m"},
                                       until=T0 + timedelta(minutes=3)), [])

    def test_detected_does_not_credit_an_alert_past_the_due_deadline(self):
        # due = attack_end + 5m + 120s slack = +7m. A behavior at +30m is a
        # different event, not a late detection of this one.
        a = alert("r1", 30, host_name="production")
        self.assertIs(classify(self._result(), [a], T0 + timedelta(minutes=40), INTERVALS),
                      Verdict.MISSED)

    def test_a_result_with_no_recorded_host_still_detects(self):
        # The query already scoped it; _on_target_host says so explicitly.
        a = alert("r1", 6, host_name="anything")
        self.assertIs(classify(self._result(host={}), [a], T0 + timedelta(minutes=10), INTERVALS),
                      Verdict.DETECTED)


class TestContestedRuleIds(unittest.TestCase):
    """Which of my rules could a LATER detonation have produced an alert for.

    This is the only question the `until` clamp needs answered, and the answer is
    almost always "none": measured 2026-08-05, 176 of the 177 target rule ids in
    the registry belong to exactly one use-case.
    """

    def det(self, minutes, rule_ids):
        return {"attack_start": (T0 + timedelta(minutes=minutes)).isoformat(),
                "rule_ids": rule_ids}

    def test_a_later_detonation_on_a_different_rule_contests_nothing(self):
        self.assertEqual(contested_rule_ids(T0.isoformat(), ["r1"], [self.det(3, ["r9"])]),
                         set())

    def test_a_later_detonation_on_the_same_rule_contests_it(self):
        self.assertEqual(contested_rule_ids(T0.isoformat(), ["r1"], [self.det(3, ["r1"])]),
                         {"r1"})

    def test_an_earlier_detonation_contests_nothing(self):
        # The clamp is an UPPER bound. What ran before me is the lower bound's job.
        self.assertEqual(contested_rule_ids(T0.isoformat(), ["r1"], [self.det(-3, ["r1"])]),
                         set())

    def test_my_own_row_does_not_contest_itself(self):
        # `> mine`, strictly. A detonation is not its own successor, and the ledger
        # list that feeds this includes the row being verified.
        self.assertEqual(contested_rule_ids(T0.isoformat(), ["r1"], [self.det(0, ["r1"])]),
                         set())

    def test_the_same_use_case_twice_in_one_night_is_a_real_contest(self):
        # Compared by RULE ID, not use-case id, so a second detonation of the same
        # use-case still clamps. Measured 2026-07-28: defender-tampering ran twice.
        self.assertEqual(contested_rule_ids(T0.isoformat(), ["r1", "r2"],
                                            [self.det(45, ["r1", "r2"])]),
                         {"r1", "r2"})

    def test_only_my_own_rules_come_back(self):
        self.assertEqual(contested_rule_ids(T0.isoformat(), ["r1"], [self.det(3, ["r1", "r9"])]),
                         {"r1"})

    def test_missing_inputs_contest_nothing(self):
        self.assertEqual(contested_rule_ids(None, ["r1"], [self.det(3, ["r1"])]), set())
        self.assertEqual(contested_rule_ids(T0.isoformat(), [], [self.det(3, ["r1"])]), set())
        self.assertEqual(contested_rule_ids(T0.isoformat(), ["r1"], None), set())


class TestAlertShapesElasticActuallyReturns(unittest.TestCase):
    """Every alert fixture in this file is a POST-flattening dict, so _flat
    returning None for every field passed the whole suite, and the one test that
    referenced query_alerts monkeypatched it away. No MISSED verdict here had ever
    been produced by a query."""

    def test_flat_reads_both_shapes(self):
        nested = {"kibana": {"alert": {"rule": {"rule_id": "r1"}}}}
        dotted = {"kibana.alert.rule.rule_id": "r1"}
        self.assertEqual(_flat(nested, "kibana.alert.rule.rule_id"), "r1")
        self.assertEqual(_flat(dotted, "kibana.alert.rule.rule_id"), "r1")
        self.assertIsNone(_flat({}, "kibana.alert.rule.rule_id"),
                          "an absent field is None, never an invented value")

    def _fake_http(self, payload):
        class _Resp:
            def __init__(self, body): self._body = body
            def __enter__(self): return self
            def __exit__(self, *a): return False
            def read(self): return json.dumps(payload).encode()

        class _Http:
            Request = urllib.request.Request
            @staticmethod
            def urlopen(req, timeout=None, context=None): return _Resp(payload)
        return _Http

    def _es_response(self, shape):
        """Two ES envelope levels, with _source in the shape under test."""
        if shape == "nested":
            src = {"kibana": {"alert": {"rule": {"rule_id": "r1", "name": "Rule X"},
                                        "original_time": (T0 + timedelta(minutes=2)).isoformat()}},
                   "@timestamp": (T0 + timedelta(minutes=2)).isoformat(),
                   "host": {"name": "production", "id": "h1"},
                   "winlog": {"computer_name": "INFECTED"},
                   "event": {"type": ["start"],
                             "ingested": (T0 + timedelta(minutes=1)).isoformat()}}
        else:
            src = {"kibana.alert.rule.rule_id": "r1", "kibana.alert.rule.name": "Rule X",
                   "kibana.alert.original_time": (T0 + timedelta(minutes=2)).isoformat(),
                   "@timestamp": (T0 + timedelta(minutes=2)).isoformat(),
                   "host.name": "production", "host.id": "h1",
                   "winlog.computer_name": "INFECTED",
                   "event.type": ["start"],
                   "event.ingested": (T0 + timedelta(minutes=1)).isoformat()}
        return {"hits": {"hits": [{"_source": src}]}}

    def test_query_alerts_returns_rows_the_classifier_can_read(self):
        for shape in ("nested", "dotted"):
            with self.subTest(shape=shape):
                rows = query_alerts("https://es", "key", ["r1"], T0.isoformat(),
                                    http=self._fake_http(self._es_response(shape)),
                                    ssl_ctx=False)
                self.assertEqual(len(rows), 1)
                self.assertEqual(rows[0]["rule_id"], "r1", f"_flat lost rule_id in the {shape} shape")
                self.assertEqual(rows[0]["host_name"], "production")
                self.assertEqual(rows[0]["winlog_computer_name"], "INFECTED")
                self.assertEqual(rows[0]["event_ingested"],
                                 (T0 + timedelta(minutes=1)).isoformat())
                r = make_result(uc(), "SUCCESS", True, attack_start=T0.isoformat(),
                                attack_end=T0.isoformat(), host={"name": "production", "id": "h1"})
                self.assertIs(classify(r, rows, T0 + timedelta(minutes=10), INTERVALS),
                              Verdict.DETECTED,
                              "a verdict produced by a real query, not by a hand-built fixture")

    def test_a_shape_drifted_response_is_None_not_an_empty_list(self):
        rows = query_alerts("https://es", "key", ["r1"], T0.isoformat(),
                            http=self._fake_http({"took": 1}), ssl_ctx=False)
        self.assertIsNone(rows, "could not measure is never a measured zero")


import verify as _v


class TestLatencyUsesTheClassifierWindow(unittest.TestCase):
    """A DETECTED row must carry a latency, including when the behavior timestamp
    lost the race to the attack_start stamp.

    Measured on the 2026-09-03 run: 3 of 8 detections came back DETECTED with
    latency None, their behavior time early by 29, 52 and 94 ms. classify() has
    tolerated exactly that since 2026-07-28 (CLOCK_SKEW_S); the latency
    computation kept a second, stricter floor, so the two disagreed about which
    alerts belong to a detonation. The miss was silent because it produced a
    MISSING number, not a wrong one.
    """

    START = "2026-09-03T13:00:01.775773+00:00"

    def _result(self):
        r = make_result({"id": "p/x", "rule_ids": ["rid-1"], "executor": "winrm_command"},
                        "ok", True)
        r.attack_start = self.START
        r.attack_end = "2026-09-03T13:00:02.347714+00:00"
        return r

    def _alert(self, behavior, written, rid="rid-1"):
        return {"rule_id": rid, "name": "R", "@timestamp": written, "original_time": behavior}

    def test_an_alert_a_few_ms_early_still_yields_a_latency(self):
        # 52 ms BEFORE attack_start - the middle of the three measured that day.
        a = self._alert("2026-09-03T13:00:01.723773+00:00", "2026-09-03T13:02:00+00:00")
        lat = _v.latency_for(self._result(), [a], {"rid-1": "5m"})
        self.assertIsNotNone(lat, "a detection must not lose its latency to a millisecond race")
        self.assertAlmostEqual(lat, 118.224227, places=3)

    def test_it_agrees_with_classify_on_the_same_alert(self):
        """The invariant that was broken: if classify says DETECTED, a latency exists."""
        r, a = self._result(), self._alert("2026-09-03T13:00:01.723773+00:00",
                                           "2026-09-03T13:02:00+00:00")
        now = _v._parse_ts("2026-09-03T13:10:00+00:00")
        self.assertEqual(classify(r, [a], now, {"rid-1": "5m"}), Verdict.DETECTED)
        self.assertIsNotNone(_v.latency_for(r, [a], {"rid-1": "5m"}))

    def test_the_tolerance_is_not_an_open_door(self):
        """5 minutes early is a different event, not a skewed clock."""
        a = self._alert("2026-09-03T12:55:00+00:00", "2026-09-03T13:02:00+00:00")
        self.assertIsNone(_v.latency_for(self._result(), [a], {"rid-1": "5m"}))

    def test_a_co_firing_rule_does_not_supply_the_latency(self):
        a = self._alert("2026-09-03T13:00:02+00:00", "2026-09-03T13:02:00+00:00", rid="other")
        self.assertIsNone(_v.latency_for(self._result(), [a],
                                         {"rid-1": "5m", "other": "5m"}))


class TestSequenceShellCreditedByComponents2026_10_16(unittest.TestCase):
    """P-D2: a sequence shell alert's own original_time is near its WRITE time, not
    the behavior it reports. Measured live 2026-10-16,
    the sequence fixture's shell
    (kibana.alert.group.id set, no building_block_type) wrote at 04:07:19Z while
    its two building blocks (building_block_type "default", group.index 0 and 1,
    same group.id) carried original_time 04:02:36Z and 04:02:38Z - the real
    behavior, nearly five minutes earlier. Scoring the shell by its own
    original_time passed the window test against an attack_start of 04:03:56Z and
    read a false DETECTED, even though the technique it reports had already
    finished before this detonation started. Anonymised the same way
    TestLsassRegression2026_07_25 is: the numbers are the measured ones, the rule
    id is a stand-in.
    """

    TARGET = "7c1d9e42-6b3a-4f1d-9a7e-2c5b8f104a3d"
    GROUP = "a9f5e6d7-0123-4abc-9def-456789abcdef"

    def _alerts(self):
        return [
            # The shell: group_id set, no building_block_type. Its own
            # original_time sits close to its write time, not to the behavior.
            {"rule_id": self.TARGET, "name": "Sequence Rule",
             "host_name": "production", "host_id": None, "event_type": ["start"],
             "@timestamp": "2026-10-16T04:07:19.500Z",
             "original_time": "2026-10-16T04:07:19.000Z",
             "group_id": self.GROUP, "building_block_type": None, "rule_version": 215},
            # The two building blocks: the REAL behavior time.
            {"rule_id": self.TARGET, "name": "Sequence Rule",
             "host_name": "production", "host_id": None, "event_type": ["start"],
             "@timestamp": "2026-10-16T04:02:40.000Z",
             "original_time": "2026-10-16T04:02:36.000Z", "group_id": self.GROUP,
             "building_block_type": "default", "group_index": 0, "rule_version": 215},
            {"rule_id": self.TARGET, "name": "Sequence Rule",
             "host_name": "production", "host_id": None, "event_type": ["start"],
             "@timestamp": "2026-10-16T04:02:42.000Z",
             "original_time": "2026-10-16T04:02:38.000Z", "group_id": self.GROUP,
             "building_block_type": "default", "group_index": 1, "rule_version": 215},
        ]

    def _result(self, attack_start):
        return make_result(
            {"id": "lateral-movement/sample-sequence",
             "rule_ids": [self.TARGET], "executor": "winrm_command"},
            "SUCCESS", True, attack_start=attack_start, attack_end=attack_start,
            host={"name": "production", "id": None})

    def test_components_before_attack_start_are_not_credited(self):
        """The real false-pass scenario: both building blocks landed BEFORE
        attack_start, so the technique this detonation ran had already finished
        before this attempt started. The old engine, scoring the shell's own
        original_time, called this DETECTED; this fix must not."""
        attack_start = "2026-10-16T04:03:56.000Z"
        now = datetime(2026, 10, 16, 4, 30, tzinfo=timezone.utc)
        v = classify(self._result(attack_start), self._alerts(), now, {self.TARGET: "5m"})
        self.assertIsNot(v, Verdict.DETECTED)

    def test_components_inside_the_window_are_credited(self):
        """The positive path: an attack_start early enough that both building
        blocks land inside the window still reads DETECTED, by the shell (the
        building blocks themselves are never a target hit)."""
        attack_start = "2026-10-16T04:02:30.000Z"
        now = datetime(2026, 10, 16, 4, 30, tzinfo=timezone.utc)
        v = classify(self._result(attack_start), self._alerts(), now, {self.TARGET: "5m"})
        self.assertIs(v, Verdict.DETECTED)
