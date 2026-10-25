"""Slice 8 acceptance, item D10: the uncontested-rule exemption is bounded by the clock-skew
tolerance, so a later detonation's co-fired alert cannot become an earlier row's DETECTED.

Green since the founder answered D10 yes (2026-10-24); it was pending_test_crossfire.py.
Measured 2026-10-24 over 5,204 ledger rows: 2,589 rows co-fired some
rule, 6,298 of those co-fired alerts were another use-case's target rule, and on 499 rows that
other use-case also ran the same night on the same host (175 distinct pairs). That is the
precondition for the exemption in verify._window_alerts (`uncontested_mine` lets a target alert
past `until` when no later detonation declares the same rule) to credit a foreign alert.

Spec: verify.UNCONTESTED_GRACE_S = CLOCK_SKEW_S. An alert of my own uncontested target rule
whose behaviour time is at or past `until + UNCONTESTED_GRACE_S` is not mine. Within the grace it
still is (the original purpose: an alert whose behaviour is my detonation's tail, placed just
after the next start by clock skew). Contested rules keep the hard clamp at `until`.
"""
import unittest
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import verify

T0 = datetime(2026, 10, 24, 1, 0, tzinfo=timezone.utc)
UNTIL = T0 + timedelta(seconds=60)      # the next detonation on this host starts 60 s after mine
INTERVALS = {"r-a": "5m"}               # my rule is due at attack_end + 300 s + 120 s slack


def iso(dt):
    return dt.isoformat().replace("+00:00", "Z")


def result():
    return SimpleNamespace(id="t/a", attack_start=iso(T0), attack_end=iso(T0 + timedelta(seconds=5)),
                           rule_ids=["r-a"], host={"name": "ws"}, executed=True)


def alert(at):
    return {"rule_id": "r-a", "name": "A", "@timestamp": iso(at), "original_time": iso(at),
            "host_name": "ws", "event_type": "info", "event_dataset": "x",
            "group_id": None, "building_block_type": None}


class BoundedExemption(unittest.TestCase):
    def test_the_bound_is_named_and_equals_the_skew_tolerance(self):
        self.assertEqual(verify.UNCONTESTED_GRACE_S, verify.CLOCK_SKEW_S)

    def test_just_after_the_next_start_is_still_mine(self):
        kept = verify._window_alerts(result(), [alert(UNTIL + timedelta(seconds=verify.CLOCK_SKEW_S - 1))],
                                     INTERVALS, until=UNTIL, contested=set())
        self.assertEqual(len(kept), 1)

    def test_well_after_the_next_start_is_not_mine_even_when_uncontested(self):
        kept = verify._window_alerts(result(), [alert(UNTIL + timedelta(seconds=120))],
                                     INTERVALS, until=UNTIL, contested=set())
        self.assertEqual(kept, [])

    def test_a_contested_rule_keeps_the_hard_clamp(self):
        kept = verify._window_alerts(result(), [alert(UNTIL + timedelta(seconds=2))],
                                     INTERVALS, until=UNTIL, contested={"r-a"})
        self.assertEqual(kept, [])


if __name__ == "__main__":
    unittest.main()
