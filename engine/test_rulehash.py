# rules/engine/test_rulehash.py
import json, os, re, subprocess, sys, unittest
from rulehash import rule_query_hash, canonical_json, HASHED_KEYS
import testenv

HERE = os.path.dirname(os.path.abspath(__file__))
# A copy of validation/fixtures/rule-hash.golden.json (three synthetic cases, shared with
# validation/lib/rule-hash.test.js), so this suite runs where validation/ does not exist.
# test_the_engine_copy_is_the_one_the_node_suite_asserts keeps the two from drifting.
GOLDEN = os.path.join(HERE, "fixtures", "rule-hash.golden.json")
SHARED_GOLDEN = os.path.join(HERE, "..", "..", "validation", "fixtures", "rule-hash.golden.json")
EXPORT = os.path.join(HERE, "..", "rules_export.ndjson")
BASE = {"type": "eql", "language": "eql", "query": "process where true", "index": ["b-*", "a-*"]}


class TestRuleHash(unittest.TestCase):
    @unittest.skipUnless(os.path.exists(SHARED_GOLDEN), "validation/ is not in this tree")
    def test_the_engine_copy_is_the_one_the_node_suite_asserts(self):
        with open(GOLDEN, "rb") as a, open(SHARED_GOLDEN, "rb") as b:
            self.assertEqual(a.read(), b.read())

    def test_every_golden_case_matches(self):
        # validation/lib/rule-hash.test.js asserts the same file.
        with open(GOLDEN, encoding="utf-8") as f:
            cases = json.load(f)
        self.assertEqual(len(cases), 3)
        for c in cases:
            self.assertEqual(rule_query_hash(c["rule"]), c["hash"], c["case"])

    def test_the_golden_cli_prints_its_line_and_exits_0(self):
        p = subprocess.run([sys.executable, os.path.join(HERE, "rulehash.py"), "--golden", GOLDEN],
                           capture_output=True, text=True, timeout=30)
        self.assertEqual(p.returncode, 0)
        self.assertEqual(p.stdout.strip(), "rule-hash: 3 of 3 golden hashes match")

    def test_a_golden_mismatch_exits_1_and_names_the_case(self):
        import tempfile
        with open(GOLDEN, encoding="utf-8") as f:
            cases = json.load(f)
        cases[1]["hash"] = "0" * 16
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as t:
            json.dump(cases, t)
        try:
            p = subprocess.run([sys.executable, os.path.join(HERE, "rulehash.py"), "--golden", t.name],
                               capture_output=True, text=True, timeout=30)
        finally:
            os.unlink(t.name)
        self.assertEqual(p.returncode, 1)
        self.assertIn(cases[1]["case"], p.stderr)

    def test_a_hash_is_16_lowercase_hex(self):
        self.assertRegex(rule_query_hash(BASE), r"^[0-9a-f]{16}$")

    def test_key_order_at_any_level_does_not_change_the_hash(self):
        with open(GOLDEN, encoding="utf-8") as f:
            g = json.load(f)[0]["rule"]
        shuffled = dict(reversed(list(g.items())))
        shuffled["filters"] = [dict(f) for f in g["filters"]]
        shuffled["filters"][0]["meta"] = dict(reversed(list(g["filters"][0]["meta"].items())))
        self.assertEqual(rule_query_hash(shuffled), rule_query_hash(g))

    def test_an_irrelevant_field_does_not_change_the_hash(self):
        extra = dict(BASE, version=9, tags=["Noise: High"], name="x", updated_at="now")
        self.assertEqual(rule_query_hash(extra), rule_query_hash(BASE))

    def test_index_order_does_not_matter_but_index_content_does(self):
        self.assertEqual(rule_query_hash(dict(BASE, index=["a-*", "b-*"])), rule_query_hash(BASE))
        self.assertNotEqual(rule_query_hash(dict(BASE, index=["a-*", "c-*"])), rule_query_hash(BASE))

    def test_a_query_change_changes_the_hash(self):
        self.assertNotEqual(rule_query_hash(dict(BASE, query="process where false")), rule_query_hash(BASE))

    def test_absent_and_null_are_the_same_but_an_empty_list_is_not_absent(self):
        self.assertEqual(rule_query_hash(dict(BASE, filters=None)), rule_query_hash(BASE))
        self.assertNotEqual(rule_query_hash(dict(BASE, filters=[])), rule_query_hash(BASE))
        self.assertNotEqual(rule_query_hash(dict(BASE, new_terms_fields=[])), rule_query_hash(BASE))

    def test_other_arrays_keep_their_order(self):
        a = dict(BASE, new_terms_fields=["x", "y"])
        b = dict(BASE, new_terms_fields=["y", "x"])
        self.assertNotEqual(rule_query_hash(a), rule_query_hash(b))

    def test_non_ascii_is_kept_not_escaped(self):
        self.assertEqual(canonical_json({"q": "café"}), '{"q":"café"}')

    def test_canonical_json_sorts_recursively_without_whitespace(self):
        self.assertEqual(canonical_json({"b": [1, {"d": 1, "c": 2}], "a": None}),
                         '{"a":null,"b":[1,{"c":2,"d":1}]}')

    @testenv.requires_live_pack
    def test_every_pack_rule_hashes_and_no_hashed_field_holds_a_float(self):
        # A float in a hashed field would print differently in JS (1.0 vs 1).
        def has_float(v):
            if isinstance(v, float):
                return True
            if isinstance(v, dict):
                return any(has_float(x) for x in v.values())
            if isinstance(v, list):
                return any(has_float(x) for x in v)
            return False
        n = 0
        with open(EXPORT, encoding="utf-8") as f:
            for line in f:
                d = json.loads(line) if line.strip() else {}
                if not d.get("rule_id"):
                    continue
                n += 1
                self.assertRegex(rule_query_hash(d), r"^[0-9a-f]{16}$")
                self.assertFalse(any(has_float(d.get(k)) for k in HASHED_KEYS), d["rule_id"])
        self.assertGreater(n, 400)


class TestLoadEnabledRulesKeepsTheHash(unittest.TestCase):
    @testenv.requires_live_pack
    def test_every_enabled_pack_rule_carries_its_hash_and_the_managed_rule_none(self):
        from ruleid import load_enabled_rules
        enabled = load_enabled_rules(EXPORT)
        by_id = {}
        with open(EXPORT, encoding="utf-8") as f:
            for line in f:
                d = json.loads(line) if line.strip() else {}
                if d.get("enabled") and d.get("name") and d.get("rule_id"):
                    by_id[d["name"]] = d
        for name, d in by_id.items():
            self.assertEqual(enabled[name]["query_hash"], rule_query_hash(d), name)
        self.assertNotIn("query_hash", enabled["Zybur Proofloop - Canary"])


if __name__ == "__main__":
    unittest.main()
