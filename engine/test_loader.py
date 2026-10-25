# rules/engine/test_loader.py
import os, unittest
from loader import load_usecases, LoaderError

HERE = os.path.dirname(__file__)
UC = os.path.join(HERE, "fixtures", "usecases")
EXPORT = os.path.join(HERE, "fixtures", "rules_export.sample.ndjson")

class TestLoader(unittest.TestCase):
    def test_loads_and_resolves_rule_ids(self):
        ucs = load_usecases(UC, EXPORT)
        by_id = {u["id"]: u for u in ucs}
        u = by_id["impact/shadow-delete-ps"]
        self.assertEqual(u["rule_ids"], ["ba1b12cd-0000-0000-0000-000000000002"])
        self.assertEqual(u["rule_meta"]["Sample Rule Two"]["interval"], "5m")
    def test_draft_excluded_by_default(self):
        ids = {u["id"] for u in load_usecases(UC, EXPORT)}
        self.assertNotIn("impact/draft-example", ids)


class TestNonDetectedNameResolution(unittest.TestCase):
    """Every use-case's rules[] is resolved, whatever its expect - but a
    `not_enabled` rule is absent from the enabled export BY DEFINITION, and on
    2026-09-03 failing it there raised LoaderError above every run.py branch and
    took the whole nightly loop down with it.
    """

    def test_a_not_enabled_usecase_naming_a_disabled_rule_loads(self):
        by_id = {u["id"]: u for u in load_usecases(UC, EXPORT)}
        self.assertIn("persistence/wmi-subscription-not-enabled", by_id)

    def test_it_carries_no_verification_target(self):
        """Only a detected use-case has a rule to verify against. A not_enabled one
        naming a switched-off rule must load with an EMPTY rule_ids rather than
        resolving a target the night could then grade."""
        by_id = {u["id"]: u for u in load_usecases(UC, EXPORT)}
        u = by_id["persistence/wmi-subscription-not-enabled"]
        self.assertEqual(u["rule_ids"], [])
        self.assertEqual(u["rule_meta"], {})

    def test_a_dangling_name_in_an_env_gap_usecase_is_still_fatal(self):
        """The check the 2026-09-02 widening exists for. It stays loud - only its
        blast radius changed."""
        broken = os.path.join(HERE, "fixtures", "usecases_unresolvable")
        with self.assertRaises(LoaderError) as cm:
            load_usecases(broken, EXPORT)
        self.assertIn("This Rule Does Not Exist Anywhere", str(cm.exception))


if __name__ == "__main__":
    unittest.main()
