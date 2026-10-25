import unittest
from datetime import datetime, timezone, timedelta

import selector as sel

NOW = datetime(2026, 7, 26, 2, 17, tzinfo=timezone.utc)


def uc(uid, severity="MEDIUM", safety="safe", **kw):
    d = {"id": uid, "severity": severity, "safety": safety, "expect": "detected"}
    d.update(kw)
    return d


def row(uid, days_ago, verdict="DETECTED"):
    return {"id": uid, "run_ts": (NOW - timedelta(days=days_ago)).isoformat(), "verdict": verdict}


class TestPool(unittest.TestCase):
    def test_only_safe_use_cases_enter_the_pool(self):
        pool = sel.safe_pool([uc("a"), uc("b", safety="supervised"), uc("c", safety="never")])
        self.assertEqual([u["id"] for u in pool], ["a"])

    # A rotation that can erase its own evidence is not a rotation: the next
    # morning's MISSED verdicts would be artefacts of the loop itself.
    def test_evidence_destroying_use_cases_are_excluded_entirely(self):
        pool = sel.safe_pool([uc("a"), uc("wipe", destroys_evidence=True)])
        self.assertEqual([u["id"] for u in pool], ["a"])

    def test_env_gap_and_draft_never_enter_the_pool(self):
        pool = sel.safe_pool([uc("a"), uc("gap", expect="env_gap"), uc("d", status="draft")])
        self.assertEqual([u["id"] for u in pool], ["a"])


class TestBounds(unittest.TestCase):
    # The spec's fixed 4-night bound is arithmetically unreachable at this pool
    # size, so the bound is computed and the real cycle length is printed.
    def test_cycle_length_is_measured_not_assumed(self):
        self.assertEqual(sel.cycle_nights(52, 10), 6)
        self.assertEqual(sel.cycle_nights(5, 10), 1)
        self.assertEqual(sel.cycle_nights(0, 10), 0)

    def test_staleness_bounds_follow_the_cycle_and_never_shrink_below_the_floor(self):
        self.assertEqual(sel.staleness_bounds(52, 10), (6, 3))
        self.assertEqual(sel.staleness_bounds(5, 10), (4, 2))

    def test_the_bound_follows_the_k_that_runs_not_the_cap(self):
        # The 2026-08-31 defect. Both derivations read K_MAX=10 while the runner
        # detonated 5 (validation/lib/live-deps.js selectK), so a 97-use-case pool on
        # a real 20-night rotation was measured against a 10-night bound: `stale` held
        # 71 of 97, and the lane that exists to INTERRUPT the debt ranking had become
        # the debt ranking. A bound shorter than the rotation that must satisfy it is
        # not a bound, it is a permanent state.
        self.assertEqual(sel.cycle_nights(97, 5), 20)
        self.assertEqual(sel.cycle_nights(97, 10), 10)
        self.assertEqual(sel.staleness_bounds(97, 5), (20, 10))
        self.assertEqual(sel.staleness_bounds(97, 8), (13, 7))

    def test_select_nightly_reports_the_cycle_it_will_actually_achieve(self):
        cases = [uc(f"t/{i:03d}") for i in range(97)]
        _, meta = sel.select_nightly(cases, [], 5, now=NOW)
        self.assertEqual(meta["k"], 5)
        self.assertEqual(meta["cycle_nights"], 20)
        self.assertEqual(meta["staleness_bound_nights"], 20)
        # And the clamp still applies to the bound, not just to the selection: asking
        # for 99 runs 10 and must declare the 10-night cycle it will really achieve.
        _, capped = sel.select_nightly(cases, [], 99, now=NOW)
        self.assertEqual(capped["k"], 10)
        self.assertEqual(capped["cycle_nights"], 10)


class TestDebt(unittest.TestCase):
    def test_never_run_outranks_every_measured_use_case(self):
        self.assertEqual(sel.debt(uc("a"), None, NOW), float("inf"))

    def test_severity_scales_debt(self):
        idx = sel.index_ledger([row("a", 3), row("b", 3)])
        high = sel.debt(uc("a", severity="HIGH"), idx["a"], NOW)
        low = sel.debt(uc("b", severity="LOW"), idx["b"], NOW)
        self.assertGreater(high, low)

    def test_a_flapping_history_weighs_more_than_a_stable_one(self):
        self.assertEqual(sel.flaky_weight(["DETECTED"] * 5), 1.0)
        self.assertGreater(sel.flaky_weight(["DETECTED", "MISSED", "DETECTED", "MISSED"]), 1.5)


class TestLedgerIndex(unittest.TestCase):
    # A re-check carries the original run_ts, so it supersedes the verdict without
    # pretending a second detonation happened.
    def test_a_recheck_updates_the_verdict_but_not_the_run_time(self):
        rows = [
            {"id": "a", "run_ts": "2026-07-25T02:20:00+00:00", "verdict": "PENDING"},
            {"id": "a", "run_ts": "2026-07-25T02:20:00+00:00", "verdict": "DETECTED",
             "rechecked_at": "2026-07-25T14:00:00+00:00"},
        ]
        idx = sel.index_ledger(rows)
        self.assertEqual(idx["a"]["last_verdict"], "DETECTED")
        self.assertEqual(idx["a"]["last_run_ts"], "2026-07-25T02:20:00+00:00")


class TestSelection(unittest.TestCase):
    def _cases(self, n=20):
        return [uc(f"t/u{i:02d}") for i in range(n)]

    def test_k_is_clamped_to_the_founder_bound(self):
        ids, meta = sel.select_nightly(self._cases(), [], 99, now=NOW)
        self.assertEqual(len(ids), 10)
        self.assertEqual(meta["k"], 10)
        ids, meta = sel.select_nightly(self._cases(), [], 1, now=NOW)
        self.assertEqual(meta["k"], 5)

    def test_selection_is_deterministic(self):
        rows = [row(f"t/u{i:02d}", i) for i in range(20)]
        a, _ = sel.select_nightly(self._cases(), rows, 7, now=NOW)
        b, _ = sel.select_nightly(self._cases(), rows, 7, now=NOW)
        self.assertEqual(a, b)

    def test_yesterdays_pending_is_injected_first(self):
        cases = self._cases()
        rows = [row(f"t/u{i:02d}", 1) for i in range(20)]
        rows.append(row("t/u19", 1, verdict="PENDING"))
        ids, meta = sel.select_nightly(cases, rows, 5, now=NOW)
        self.assertEqual(ids[0], "t/u19")
        self.assertEqual(meta["pending"], 1)

    def test_a_suspected_regression_comes_next(self):
        cases = self._cases()
        rows = [row(f"t/u{i:02d}", 1) for i in range(20)]
        rows.append(row("t/u05", 1, verdict="MISSED"))   # healthy then missed
        ids, meta = sel.select_nightly(cases, rows, 5, now=NOW)
        self.assertIn("t/u05", ids)
        self.assertEqual(meta["regressions"], 1)

    def test_only_pool_members_are_ever_selected(self):
        cases = self._cases(6) + [uc("bad", safety="supervised"), uc("wipe", destroys_evidence=True)]
        ids, _ = sel.select_nightly(cases, [], 6, now=NOW)
        self.assertNotIn("bad", ids)
        self.assertNotIn("wipe", ids)

    def test_one_domain_controller_case_is_reserved_each_night(self):
        cases = self._cases(20) + [uc("credential-access/dcsync", target="domain_controller")]
        # Every workstation case is much older, so ordinary debt ordering would
        # leave the fresh DC case outside a five-slot selection.
        rows = [row(f"t/u{i:02d}", 30) for i in range(20)]
        rows.append(row("credential-access/dcsync", 0))
        ids, meta = sel.select_nightly(cases, rows, 5, now=NOW)
        self.assertEqual(ids[0], "credential-access/dcsync")
        self.assertIn("domain_controller", meta["targets"])
        self.assertEqual(len(ids), 5)

    def test_an_empty_safe_pool_selects_nothing_rather_than_reaching_wider(self):
        ids, meta = sel.select_nightly([uc("a", safety="supervised")], [], 5, now=NOW)
        self.assertEqual(ids, [])
        self.assertEqual(meta["pool"], 0)

    def test_never_run_use_cases_are_taken_before_stale_ones(self):
        cases = [uc("t/old"), uc("t/new")]
        ids, _ = sel.select_nightly(cases, [row("t/old", 30)], 5, now=NOW)
        self.assertEqual(ids[0], "t/new")

    def test_the_whole_safe_pool_is_reached_inside_the_measured_cycle(self):
        cases = self._cases(20)
        rows, seen = [], set()
        now = NOW
        for _ in range(sel.cycle_nights(20, 10)):
            ids, _ = sel.select_nightly(cases, rows, 10, now=now)
            seen.update(ids)
            rows.extend({"id": i, "run_ts": now.isoformat(), "verdict": "DETECTED"} for i in ids)
            now += timedelta(days=1)
        self.assertEqual(seen, {u["id"] for u in cases})


class TestStandingMissedIsRetested(unittest.TestCase):
    """Measured on the live ledger 2026-08-05: EIGHT pool use-cases sat on a MISSED
    verdict 6-8 nights old and none was in the next night's selection. A MISSED
    earned no priority and `debt()` ranks on age alone, so the worst result the loop
    can produce was the one result it never re-measured.
    """

    def test_a_missed_outranks_a_fresher_healthy_use_case(self):
        cases = [uc("t/missed"), uc("t/fine")]
        # The MISSED is the OLDER run, so age alone would already prefer it. Give
        # the healthy one the older timestamp so only the lane can explain the order.
        rows = [row("t/missed", 2, "MISSED"), row("t/fine", 20, "DETECTED")]
        ids, meta = sel.select_nightly(cases, rows, 5, now=NOW)
        self.assertEqual(ids[0], "t/missed")
        self.assertEqual(meta["missed"], 1)

    def test_a_missed_that_keeps_missing_stops_holding_a_slot(self):
        # Three consecutive misses is a finding for a human, not news for the loop.
        # Without this bound a use-case that can NEVER fire here (no telemetry, wrong
        # payload) would take a nightly slot every night forever, which is how
        # yesterday's PENDING used to starve the whole rotation.
        cases = [uc("t/broken")]
        rows = [row("t/broken", 6, "MISSED"), row("t/broken", 5, "MISSED"),
                row("t/broken", 4, "MISSED"), row("t/broken", 3, "MISSED")]
        _, meta = sel.select_nightly(cases, rows, 5, now=NOW)
        self.assertEqual(meta["missed"], 0, "past MISSED_RETEST_MAX it is someone's to-do")

    def test_a_resolved_miss_leaves_the_lane(self):
        cases = [uc("t/fixed")]
        rows = [row("t/fixed", 3, "MISSED"), row("t/fixed", 2, "DETECTED")]
        _, meta = sel.select_nightly(cases, rows, 5, now=NOW)
        self.assertEqual(meta["missed"], 0)

    def test_a_prevented_verdict_is_not_a_miss(self):
        cases = [uc("t/blocked")]
        rows = [row("t/blocked", 3, "PREVENTED")]
        _, meta = sel.select_nightly(cases, rows, 5, now=NOW)
        self.assertEqual(meta["missed"], 0)


class TestPendingLaneIsBounded(unittest.TestCase):
    """Lane 1 held two use-cases for eleven and nine consecutive detonations.

    Measured on the live ledger 2026-08-26.
    Two use-cases ended PENDING repeatedly, so lane 1 consumed a disproportionate
    share of the rotation and neither produced a measurement. The root cause is fixed in
    validation/run.js (the carry-over re-check runs BEFORE select now); this is the
    backstop for a row that re-checking cannot resolve, and it is the same bound
    lane 3 has had since 2026-08-05 - whose comment already said an unfirable
    use-case must not hold a slot "exactly the way yesterday's PENDING used to".
    """

    def test_a_fresh_pending_still_leads(self):
        cases = [uc("t/pending"), uc("t/fine")]
        rows = [row("t/pending", 1, "PENDING"), row("t/fine", 20, "DETECTED")]
        ids, meta = sel.select_nightly(cases, rows, 5, now=NOW)
        self.assertEqual(ids[0], "t/pending")
        self.assertEqual(meta["pending"], 1)

    def test_a_pending_that_never_settles_stops_holding_a_slot(self):
        cases = [uc("t/stuck")]
        rows = [row("t/stuck", 4, "PENDING"), row("t/stuck", 3, "PENDING"),
                row("t/stuck", 2, "PENDING"), row("t/stuck", 1, "PENDING")]
        _, meta = sel.select_nightly(cases, rows, 5, now=NOW)
        self.assertEqual(meta["pending"], 0,
                         "past PENDING_RETEST_MAX it is someone's to-do, not a nightly slot")

    def test_the_bound_counts_detonations_and_not_rows(self):
        # THE trap in writing this bound. Every detonation writes PENDING once and
        # every settle poll appends another, so ONE night contributes a dozen PENDING
        # entries to the raw verdict list. A row-wise count would fire on night one
        # and un-prioritise a use-case that is behaving exactly as designed.
        cases = [uc("t/one_night")]
        rows = [row("t/one_night", 1, "PENDING") for _ in range(12)]
        _, meta = sel.select_nightly(cases, rows, 5, now=NOW)
        self.assertEqual(meta["pending"], 1, "twelve rows from ONE detonation is one night")

    def test_a_pending_that_re_checking_resolves_leaves_the_lane(self):
        # What the carry-over re-check does every morning: the row keeps its original
        # run_ts and the new verdict supersedes it.
        cases = [uc("t/settled")]
        rows = [row("t/settled", 3, "PENDING"), row("t/settled", 2, "PENDING"),
                row("t/settled", 1, "PENDING"),
                dict(row("t/settled", 1, "PREVENTED"), rechecked_at="later")]
        _, meta = sel.select_nightly(cases, rows, 5, now=NOW)
        self.assertEqual(meta["pending"], 0)

    def test_an_over_bound_pending_is_never_called_a_regression(self):
        # It falls to the STALENESS lane, never to lanes 2 or 3, whose tests read the
        # last REAL verdict - which for a row that is pending NOW belongs to some
        # earlier night. Calling an unmeasured use-case a regression on a verdict it
        # has since superseded would be a worse lie than the starvation being fixed.
        cases = [uc("t/stuck")]
        rows = [row("t/stuck", 9, "DETECTED"), row("t/stuck", 8, "MISSED"),
                row("t/stuck", 4, "PENDING"), row("t/stuck", 3, "PENDING"),
                row("t/stuck", 2, "PENDING"), row("t/stuck", 1, "PENDING")]
        _, meta = sel.select_nightly(cases, rows, 5, now=NOW)
        self.assertEqual(meta["pending"], 0)
        self.assertEqual(meta["regressions"], 0)
        self.assertEqual(meta["missed"], 0)

    def test_consecutive_pending_detonations_counts_back_from_the_newest(self):
        idx = sel.index_ledger([
            row("t/x", 5, "PENDING"), row("t/x", 4, "DETECTED"),
            row("t/x", 3, "PENDING"), row("t/x", 2, "PENDING"),
        ])
        self.assertEqual(sel.consecutive_pending_detonations(idx["t/x"]), 2)
        self.assertEqual(sel.consecutive_pending_detonations(None), 0)


class TestRegressionLaneIgnoresPending(unittest.TestCase):
    """The lane built to re-test a detection that just broke could not fire at all.

    Every detonation writes PENDING first and the re-check supersedes it by
    APPENDING, so the raw verdict history reads [PENDING, PENDING, MISSED] and the
    `vs[-2]` test saw PENDING. Measured 2026-08-05 across the live pool: `vs[-2]`
    was PENDING for 81 of 82 members, so the lane was structurally dead.
    """

    def test_a_regression_is_seen_through_the_pending_rows_between(self):
        cases = [uc("t/reg")]
        rows = [row("t/reg", 4, "DETECTED"),
                row("t/reg", 3, "PENDING"), row("t/reg", 3, "PENDING"),
                row("t/reg", 3, "MISSED")]
        _, meta = sel.select_nightly(cases, rows, 5, now=NOW)
        self.assertEqual(meta["regressions"], 1)
        self.assertEqual(meta["missed"], 0, "a regression is claimed by the earlier lane")

    def test_an_abort_is_not_a_healthy_prior_run(self):
        # ABORT is the loop describing itself: the attack never executed. Counting it
        # as the "one healthy run" before a miss would invent a regression.
        cases = [uc("t/ab")]
        rows = [row("t/ab", 4, "ABORT"), row("t/ab", 3, "MISSED")]
        _, meta = sel.select_nightly(cases, rows, 5, now=NOW)
        self.assertEqual(meta["regressions"], 0)


class TestRowsWithVerdict(unittest.TestCase):
    def test_the_latest_row_per_id_decides(self):
        rows = [
            {"id": "a", "run_ts": "1", "verdict": "MISSED"},
            {"id": "a", "run_ts": "1", "verdict": "DETECTED", "rechecked_at": "2"},
            {"id": "b", "run_ts": "1", "verdict": "MISSED"},
        ]
        self.assertEqual([r["id"] for r in sel.rows_with_verdict(rows, ("MISSED",))], ["b"])


class TestPendingRows(unittest.TestCase):
    def test_only_the_latest_row_per_id_counts(self):
        rows = [
            {"id": "a", "run_ts": "1", "verdict": "PENDING"},
            {"id": "a", "run_ts": "1", "verdict": "DETECTED", "rechecked_at": "2"},
            {"id": "b", "run_ts": "1", "verdict": "PENDING"},
        ]
        self.assertEqual([r["id"] for r in sel.pending_rows(rows)], ["b"])


if __name__ == "__main__":
    unittest.main()


class TestSelectNightlyZero(unittest.TestCase):
    """rules/engine/run.py used `if args.select_nightly:`, so --select-nightly 0
    was falsy and fell through to the DETONATION branch. Asking for zero use-cases
    must select zero, not fire the default set."""

    def test_zero_selects_nothing(self):
        ids, meta = sel.select_nightly(
            [{"id": "a/one", "technique": "T1", "tactic": "t", "status": "active"}],
            [], 0, now=NOW)
        self.assertEqual(ids, [])

    def test_run_py_tests_is_not_none_rather_than_truthiness(self):
        # The guard itself, because the branch it protects shells out to CALDERA
        # and cannot be driven from a unit test.
        import pathlib
        src = pathlib.Path(__file__).with_name("run.py").read_text()
        self.assertIn("if args.select_nightly is not None:", src)
        self.assertNotIn("if args.select_nightly:", src)
