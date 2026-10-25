# rules/engine/test_ruleid.py
import os, json, pathlib, unittest
from ruleid import build_lock, load_enabled_rules, resolve_rule_names, RuleNameError

FIX = os.path.join(os.path.dirname(__file__), "fixtures", "rules_export.sample.ndjson")

class TestRuleId(unittest.TestCase):
    def test_load_enabled_rules_keys_by_name(self):
        rules = load_enabled_rules(FIX)
        self.assertIn("LSASS Memory Dump Creation", rules)
        self.assertEqual(rules["LSASS Memory Dump Creation"]["interval"], "5m")
    def test_build_lock_maps_name_to_rule_id(self):
        uc = [{"id": "c/x", "rules": ["LSASS Memory Dump Creation"], "expect": "detected"}]
        lock = build_lock(uc, FIX)
        self.assertEqual(lock["LSASS Memory Dump Creation"]["rule_id"],
                         "ba1b12cd-0000-0000-0000-000000000001")
    def test_build_lock_fails_loud_on_unknown_name(self):
        uc = [{"id": "c/x", "rules": ["No Such Rule"], "expect": "detected"}]
        with self.assertRaises(RuleNameError) as cm:
            build_lock(uc, FIX)
        self.assertIn("No Such Rule", str(cm.exception))
        self.assertIn("c/x", str(cm.exception))
    def test_env_gap_usecase_does_not_abort(self):
        uc = [{"id": "c/x", "rules": [], "expect": "env_gap"}]
        self.assertEqual(build_lock(uc, FIX), {})


class TestResolveRuleNames(unittest.TestCase):
    """What "the name resolves" MEANS depends on expect, and conflating the three
    cost the 2026-09-03 nightly run its whole loop.

    Before 2026-09-02 only expect:detected use-cases were resolved at all, so a
    typo in a non-detected one sat silent. The widening was right; treating all
    three expects identically was not, because a not_enabled rule is absent from
    the enabled export BY DEFINITION.
    """

    def setUp(self):
        self.enabled = load_enabled_rules(FIX)

    def test_detected_naming_an_unknown_rule_is_an_error(self):
        errs = resolve_rule_names({"rules": ["No Such Rule"], "expect": "detected"}, self.enabled)
        self.assertEqual(len(errs), 1)
        self.assertIn("No Such Rule", errs[0])

    def test_expect_defaults_to_detected(self):
        self.assertEqual(len(resolve_rule_names({"rules": ["No Such Rule"]}, self.enabled)), 1)

    def test_env_gap_naming_an_unknown_rule_is_STILL_an_error(self):
        """env_gap says the ENVIRONMENT cannot produce the telemetry. The rule
        itself is live, so it has to be in the enabled export - which is why 59 of
        the 60 env_gap use-cases resolved cleanly and the 60th was mislabelled."""
        errs = resolve_rule_names({"rules": ["No Such Rule"], "expect": "env_gap"}, self.enabled)
        self.assertEqual(len(errs), 1)

    def test_not_enabled_naming_a_disabled_rule_is_NOT_an_error(self):
        """The regression that took the loop down: this is the field's only honest
        use, and requiring the name to be in the ENABLED export made it a crash."""
        self.assertEqual(
            resolve_rule_names({"rules": ["Suspicious WMI Event Subscription Created"],
                                "expect": "not_enabled"}, self.enabled),
            [])

    def test_not_enabled_naming_an_ENABLED_rule_is_an_error(self):
        """The drift that IS checkable offline: somebody enabled the rule and the
        use-case still claims it is off, so a verifiable detection goes unmeasured."""
        errs = resolve_rule_names({"rules": ["LSASS Memory Dump Creation"],
                                   "expect": "not_enabled"}, self.enabled)
        self.assertEqual(len(errs), 1)
        self.assertIn("flip expect to detected", errs[0])

    def test_an_empty_rules_list_resolves_to_nothing(self):
        self.assertEqual(resolve_rule_names({"rules": [], "expect": "env_gap"}, self.enabled), [])
        self.assertEqual(resolve_rule_names({"expect": "env_gap"}, self.enabled), [])

    def test_the_runtime_and_the_gate_share_this_one_implementation(self):
        """A second copy becomes a second answer - the safe-pool probe already
        proved that here. loader.py (runtime) and lint.py (CI gate) must both call
        this function rather than re-deriving the rules."""
        here = pathlib.Path(__file__).parent
        for fn in ("loader.py", "lint.py"):
            src = (here / fn).read_text()
            self.assertIn("resolve_rule_names", src, f"{fn} must use the shared check")
            self.assertNotIn("not in enabled export", src,
                             f"{fn} re-implements name resolution instead of calling it")


if __name__ == "__main__":
    unittest.main()
