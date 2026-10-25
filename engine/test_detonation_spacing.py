# rules/engine/test_detonation_spacing.py
"""Detonations are spaced so the verifier's neighbour clamps stay outside the
clock-skew tolerance (regression 2026-09-29: 8 use-cases ran 0.5-1.1s apart in
one invocation, `prev_end_bound` clamped mshta's own Defend prevention onto the
previous row, and a real PREVENTED was recorded as MISSED with VERIFY red)."""
import io
import json
import os
import pathlib
import tempfile
import unittest
from contextlib import redirect_stderr
from datetime import datetime, timedelta, timezone

import run as runmod
import verify as verifymod
from verify import classify
from result import make_result, Verdict

T0 = datetime(2026, 9, 29, 4, 4, 0, tzinfo=timezone.utc)


def _uc(uid):
    return {"id": uid, "rule_ids": ["r1"], "executor": "winrm_command"}


def _det(uid, offset_s):
    t = (T0 + timedelta(seconds=offset_s)).isoformat()
    return make_result(_uc(uid), "SUCCESS", True, attack_start=t, attack_end=t)


class TestSpacingGuard(unittest.TestCase):
    def _warn(self, results):
        buf = io.StringIO()
        with redirect_stderr(buf):
            runmod._warn_if_detonations_too_close(results)
        return buf.getvalue()

    def test_it_warns_when_two_detonations_are_inside_the_skew_tolerance(self):
        # The exact 2026-09-29 shape: consecutive detonations ~0.5s apart.
        out = self._warn([_det("a", 0), _det("b", 0.5)])
        self.assertIn("WARNING", out)
        self.assertIn("0.50s apart", out)
        self.assertIn("a", out)
        self.assertIn("b", out)

    def test_it_is_silent_when_detonations_are_spaced_past_the_tolerance(self):
        out = self._warn([_det("a", 0), _det("b", 10), _det("c", 20)])
        self.assertEqual(out, "")

    def test_the_floor_is_the_verifier_clock_skew_tolerance(self):
        # The guard must track verify.CLOCK_SKEW_S, not a private copy: they are the
        # same invariant. A gap just under it warns, just over it does not.
        skew = verifymod.CLOCK_SKEW_S
        self.assertEqual(self._warn([_det("a", 0), _det("b", skew + 0.5)]), "")
        self.assertIn("WARNING", self._warn([_det("a", 0), _det("b", skew - 0.5)]))

    def test_rows_without_an_attack_start_are_ignored(self):
        skipped = make_result(_uc("skipped"), "ERROR: missing target config", False)
        out = self._warn([skipped, _det("a", 0), _det("b", 20)])
        self.assertEqual(out, "")

    def test_it_sorts_by_start_so_ledger_order_does_not_matter(self):
        # Results can reach the guard out of start order; it compares by time.
        out = self._warn([_det("late", 20), _det("early", 0), _det("mid", 0.4)])
        self.assertIn("WARNING", out)
        self.assertIn("0.40s apart", out)


class TestSpacingWiring(unittest.TestCase):
    """The detonation loop itself needs CALDERA, dedup, firewall and WinRM, so its
    wiring is asserted from source the same way --ensure-agent's placement is."""

    SRC = pathlib.Path(runmod.__file__).read_text()

    def test_the_gap_is_configurable_and_defaults_to_ten_seconds(self):
        self.assertEqual(runmod.DETONATION_GAP_S, 10.0)
        self.assertIn('os.environ.get("ZYBUR_DETONATION_GAP_S"', self.SRC)

    def test_the_loop_waits_through_the_ledger_aware_helper_before_the_handler(self):
        self.assertIn("_wait_for_detonation_gap(host, results)", self.SRC)
        self.assertLess(self.SRC.index("_wait_for_detonation_gap(host, results)"),
                        self.SRC.index("r = handler(u, ctx)"))

    def test_the_in_process_only_gate_is_gone(self):
        # 49bbb56 gated the sleep on an in-process counter. The nightly runs one
        # use-case per invocation, so the counter was 0 every time and the sleep
        # never ran (2026-09-30). Do not bring that gate back.
        self.assertNotIn("if detonated and DETONATION_GAP_S > 0:", self.SRC)
        self.assertNotIn("time.sleep(DETONATION_GAP_S)", self.SRC)

    def test_the_guard_runs_after_the_loop_over_the_collected_results(self):
        self.assertIn("_warn_if_detonations_too_close(results)", self.SRC)
        self.assertLess(self.SRC.index("results.append(r)"),
                        self.SRC.index("_warn_if_detonations_too_close(results)"))


class TestCrossInvocationGap(unittest.TestCase):
    """The gap is measured from the LEDGER, so it holds when every detonation is its
    own engine invocation, which is how validation/run.js drives the nightly
    (`d.detonate([id])`). Times below are the real 2026-09-30 ledger rows: the first
    night on 49bbb56, whose in-process gate never fired."""

    PROD = {"name": "production", "id": None, "aliases": []}
    DC = {"name": "dc1", "id": None, "aliases": []}
    WPAD = {"id": "credential-access/sample-one",
            "host": {"name": "dc1"}, "verdict": "PENDING",
            "attack_start": "2026-09-30T04:03:46.021023+00:00",
            "attack_end": "2026-09-30T04:03:55.399952+00:00"}
    MSHTA = {"id": "defense-evasion/sample-two",
             "host": {"name": "production"}, "verdict": "PENDING",
             "attack_start": "2026-09-30T04:03:55.883656+00:00",
             "attack_end": "2026-09-30T04:03:56.229799+00:00"}
    MSHTA_END = datetime(2026, 9, 30, 4, 3, 56, 229799, tzinfo=timezone.utc)

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.addCleanup(setattr, runmod, "LEDGER", runmod.LEDGER)
        runmod.LEDGER = os.path.join(tmp.name, "ledger.jsonl")
        self.slept = []

    def _ledger(self, *rows):
        with open(runmod.LEDGER, "w") as f:
            for row in rows:
                f.write(json.dumps(row) + "\n")

    def _wait(self, host, now, results=(), gap_s=10.0):
        return runmod._wait_for_detonation_gap(host, list(results), gap_s=gap_s, now=now,
                                               sleep=self.slept.append)

    def _result(self, host, end):
        r = make_result(_uc("x"), "SUCCESS", True, attack_start=end.isoformat(),
                        attack_end=end.isoformat())
        r.host = host
        return r

    def test_a_previous_invocation_on_the_same_host_is_waited_for(self):
        # rdp-shadowing really started 1.046s after mshta ended; now it waits the rest.
        self._ledger(self.WPAD, self.MSHTA, self.MSHTA)  # recheck re-appends rows
        waited = self._wait(self.PROD, self.MSHTA_END + timedelta(seconds=1.046016))
        self.assertAlmostEqual(waited, 8.953984, places=5)
        self.assertEqual(len(self.slept), 1)
        self.assertAlmostEqual(self.slept[0], 8.953984, places=5)

    def test_a_detonation_on_another_host_is_not_waited_for(self):
        # mshta followed the DC's WPAD test by 0.48s. The verifier's clamps are per
        # host, so the DC row cannot bound a production window.
        self._ledger(self.WPAD)
        self.assertEqual(self._wait(self.PROD, datetime(2026, 9, 30, 4, 3, 55, 883656,
                                                        tzinfo=timezone.utc)), 0.0)
        self.assertEqual(self.slept, [])

    def test_no_wait_once_the_gap_has_already_passed(self):
        self._ledger(self.MSHTA)
        self.assertEqual(self._wait(self.PROD, self.MSHTA_END + timedelta(seconds=12)), 0.0)
        self.assertEqual(self.slept, [])

    def test_this_invocations_own_results_count_too(self):
        # The multi --id CLI path: the previous row is not in the ledger yet.
        now = datetime(2026, 9, 30, 12, 0, 0, tzinfo=timezone.utc)
        waited = self._wait(self.PROD, now, [self._result(self.PROD, now - timedelta(seconds=0.5))])
        self.assertAlmostEqual(waited, 9.5)

    def test_another_hosts_result_in_this_invocation_is_ignored(self):
        now = datetime(2026, 9, 30, 12, 0, 0, tzinfo=timezone.utc)
        self.assertEqual(self._wait(self.PROD, now, [self._result(self.DC, now)]), 0.0)

    def test_a_config_skipped_row_costs_no_wait(self):
        skipped = make_result(_uc("skipped"), "ERROR: missing target config", False)
        skipped.host = self.PROD
        now = datetime(2026, 9, 30, 12, 0, 0, tzinfo=timezone.utc)
        self.assertEqual(self._wait(self.PROD, now, [skipped]), 0.0)

    def test_zero_gap_disables_the_wait(self):
        self._ledger(self.MSHTA)
        self.assertEqual(self._wait(self.PROD, self.MSHTA_END, gap_s=0), 0.0)
        self.assertEqual(self.slept, [])

    def test_an_end_stamped_in_the_future_waits_at_most_the_gap(self):
        self._ledger(self.MSHTA)
        waited = self._wait(self.PROD, self.MSHTA_END - timedelta(seconds=30))
        self.assertEqual(waited, 10.0)

    def test_a_malformed_ledger_end_is_skipped_not_fatal(self):
        self._ledger(dict(self.MSHTA, attack_end="not-a-time"), self.WPAD)
        now = datetime(2026, 9, 30, 4, 3, 57, tzinfo=timezone.utc)
        self.assertEqual(self._wait(self.PROD, now), 0.0)

    def test_no_ledger_file_means_no_wait(self):
        self.assertEqual(self._wait(self.PROD, self.MSHTA_END), 0.0)


class TestRegression20260929Mshta(unittest.TestCase):
    """The exact 2026-09-29 verdict, at the classifier level, with the real times.

    mshta.exe was blocked by Elastic Defend; the two prevention alerts carried
    mshta's command line, behaviour time 04:04:16.330Z (Windows clock, ~0.8s
    behind the engine host). The previous detonation (Kerberos) ended at
    04:04:16.608Z on the engine clock, only ~0.5s before mshta started. When the
    detonations run that close, prev_end_bound clamps mshta's window at the
    Kerberos end and drops the prevention -> MISSED. Spaced properly, the prevention
    is inside mshta's window -> PREVENTED. The fix is the spacing, not this class;
    this pins the mechanism so it cannot silently come back."""

    MSHTA_START = datetime(2026, 9, 29, 4, 4, 17, 135678, tzinfo=timezone.utc)
    MSHTA_END = datetime(2026, 9, 29, 4, 4, 17, 510280, tzinfo=timezone.utc)
    KERB_END = datetime(2026, 9, 29, 4, 4, 16, 608000, tzinfo=timezone.utc)  # ~0.5s before
    NOW = datetime(2026, 9, 29, 4, 20, 0, tzinfo=timezone.utc)  # well past due

    def _mshta(self):
        return make_result(_uc("defense-evasion/mshta"), "SUCCESS", True,
                           attack_start=self.MSHTA_START.isoformat(),
                           attack_end=self.MSHTA_END.isoformat())

    def _prevention(self):
        # is_prevention reads event_type "denied"; behavior_ts reads original_time.
        return {"rule_id": "9a1a2dae", "name": "Malicious Behavior Prevention Alert: "
                "Suspicious Windows Command Shell Execution", "host_name": "production",
                "host_id": None, "event_type": ["info", "denied"],
                "original_time": datetime(2026, 9, 29, 4, 4, 16, 330000,
                                          tzinfo=timezone.utc).isoformat(),
                "@timestamp": datetime(2026, 9, 29, 4, 5, 3, 365000,
                                       tzinfo=timezone.utc).isoformat()}

    def test_back_to_back_clamps_the_prevention_and_reads_MISSED(self):
        # since = the Kerberos end, i.e. what prev_end_bound produces with no gap.
        v = classify(self._mshta(), [self._prevention()], self.NOW, {"r1": "5m"},
                     since=self.KERB_END)
        self.assertIs(v, Verdict.MISSED,
                      "reproduces the 2026-09-29 false MISSED that reddened VERIFY")

    def test_spaced_ten_seconds_the_prevention_is_ours_and_reads_PREVENTED(self):
        # A >=10s gap puts the previous end below the clock-skew floor, so it stops
        # binding and the prevention lands in mshta's own window.
        spaced_prev_end = self.MSHTA_START - timedelta(seconds=10)
        v = classify(self._mshta(), [self._prevention()], self.NOW, {"r1": "5m"},
                     since=spaced_prev_end)
        self.assertIs(v, Verdict.PREVENTED, "the spacing fix restores the true verdict")

    def test_with_no_previous_detonation_it_is_also_PREVENTED(self):
        v = classify(self._mshta(), [self._prevention()], self.NOW, {"r1": "5m"}, since=None)
        self.assertIs(v, Verdict.PREVENTED)


if __name__ == "__main__":
    unittest.main()
