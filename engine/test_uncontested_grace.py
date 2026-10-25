"""The D10 knob (verify.UNCONTESTED_GRACE_S / ZYBUR_UNCONTESTED_GRACE_S) does what the replay
measurement says it does.

test_crossfire.py is the contract for the DEFAULT (the founder answered D10 yes, 2026-10-24: the
bound is CLOCK_SKEW_S). These tests patch the constant, so they hold whatever the default is:
None leaves the exemption unbounded, a number bounds it, a contested rule is never touched, an
unset or empty environment value means the default, and a malformed one is an error rather than
a silent fall back (a replay that "shows no difference" because of a typo would mislead).
"""
import unittest
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest import mock

import verify

T0 = datetime(2026, 10, 24, 1, 0, tzinfo=timezone.utc)
UNTIL = T0 + timedelta(seconds=60)
INTERVALS = {"r-a": "5m"}
ENV = "ZYBUR_UNCONTESTED_GRACE_S"


def iso(dt):
    return dt.isoformat().replace("+00:00", "Z")


def result():
    return SimpleNamespace(id="t/a", attack_start=iso(T0), attack_end=iso(T0 + timedelta(seconds=5)),
                           rule_ids=["r-a"], host={"name": "ws"}, executed=True)


def alert(at):
    return {"rule_id": "r-a", "name": "A", "@timestamp": iso(at), "original_time": iso(at),
            "host_name": "ws", "event_type": "info", "event_dataset": "x",
            "group_id": None, "building_block_type": None}


def kept(seconds_past_until, grace, contested=()):
    with mock.patch.object(verify, "UNCONTESTED_GRACE_S", grace):
        return verify._window_alerts(result(), [alert(UNTIL + timedelta(seconds=seconds_past_until))],
                                     INTERVALS, until=UNTIL, contested=set(contested))


class BoundOff(unittest.TestCase):
    def test_none_keeps_an_uncontested_alert_however_late(self):
        # None is how a caller (or a test) switches the bound off; the environment's way is a large number.
        self.assertEqual(len(kept(120, None)), 1)


class BoundOn(unittest.TestCase):
    def test_inside_the_grace_is_still_mine(self):
        self.assertEqual(len(kept(4, 5)), 1)

    def test_at_the_grace_is_not_mine(self):
        self.assertEqual(kept(5, 5), [])

    def test_well_past_the_grace_is_not_mine(self):
        self.assertEqual(kept(120, 5), [])

    def test_a_contested_rule_keeps_the_hard_clamp_with_or_without_the_grace(self):
        for grace in (None, 5, 30):
            self.assertEqual(kept(2, grace, contested={"r-a"}), [], grace)

    def test_an_alert_before_until_is_never_touched_by_the_grace(self):
        self.assertEqual(len(kept(-10, 0)), 1)


class FromEnvironment(unittest.TestCase):
    def test_unset_and_empty_mean_the_clock_skew_tolerance(self):
        self.assertEqual(verify._grace_from_env({}), verify.CLOCK_SKEW_S)
        self.assertEqual(verify._grace_from_env({ENV: ""}), verify.CLOCK_SKEW_S)
        self.assertEqual(verify._grace_from_env({ENV: "  "}), verify.CLOCK_SKEW_S)

    def test_a_very_large_value_restores_the_unbounded_exemption(self):
        # How a replay is compared with and without the bound now that the bound is the default.
        grace = verify._grace_from_env({ENV: "31536000"})
        self.assertEqual(len(kept(120, grace)), 1)

    def test_whole_seconds_are_read(self):
        self.assertEqual(verify._grace_from_env({ENV: "5"}), 5)
        self.assertEqual(verify._grace_from_env({ENV: "0"}), 0)

    def test_junk_is_an_error_that_names_the_variable(self):
        for bad in ("five", "-1", "5.5", "1e3"):
            with self.assertRaises(ValueError) as cm:
                verify._grace_from_env({ENV: bad})
            self.assertIn(ENV, str(cm.exception))


if __name__ == "__main__":
    unittest.main()
